/*jshint esversion: 6 */
/*jshint node: true*/

var fs      = require('fs');
var path    = require('path');
var sha1    = require('sha1');

const GLOBAL_HEADER_LENGTH = 24; // bytes - number of bytes of the pcap file header
const PACKET_HEADER_LENGTH = 16; // bytes - number of bytes of the packet header


class PcapParser
{
    constructor(opt)
    {
        this.file       = opt.file;             // file to parse
        this.watch      = opt.watch || false;   // watch the file for changes?
        this.startByte  = opt.start || 0;       // the byte for starting reading the file
        this.hash  		= opt.hash  || false;   // create hash over the packet

        this.buffer     = null;                 // is the file buffer used to read the data
        this.streamOpen = false;                // is used to define, when the stream to the files are open
        this.state      = 0;                    // is the current parsing state 0 = global header, 1 = packet header, 2 = packet body
        this.events     = {};                   // stores the event which can be called while parsing: fileheader, packetheader, packetdata, packet, finished
        this.endianness = null;                 // endianness of the file (used for reading bytes in correct direction)


        this.globalHeader       = null;         // stored the global header of the file after parsing
        this.lastPacketHeader   = null;         // used to store the last parsed packet header
        this.lastPacketData     = null;         // used to store the last parsed packet data

        this.fsWatcher          = null;

        this.packetCount = 0;

        // start file watch
        if(this.watch)
        {
            this.startWatch();
        }
    }


    on(event, method)
    {
        this.events[event] = method;

        return this;
    }


    startWatch()
    {
        // store the class as var for inblock use
        var self = this;

        var dirname = path.dirname(this.file);
        var name    = path.basename(this.file);

        console.log('start watching:', dirname, name);
        // create file watching
        this.fsWatcher = fs.watch(dirname, {encoding: null}, function(eventType, filename) {

            if(filename === name)
            {
                if(fs.existsSync(self.file))
                {
                    // start parsing
                    self.parse();
                }                
            }

        });
    }

    stopWatch()
    {
        if(this.fsWatcher)
        {
            this.fsWatcher.close();
        }
    }


    parse()
    {
        // do not parse if a stream is already open
        if(this.streamOpen === true)
            return;

        // set up file stream and parse
        this.streamOpen = true;

        // open the file stream to the given file
        var stream = fs.createReadStream(this.file, {
            flags: 'r',
            encoding: null, // use 'utf-8' for a string
            start: this.startByte
        });

        // clear buffer
        this.buffer 	 = null;

        // reset packet count 
        this.packetCount = 0;

        var self = this;

        // on data check the buffer and extend startl length if file watchting
        stream.on('data', function(data){
            
            // raise start bytes on file watching
            if(self.watch === true)
            {
                self.startByte += data.length;  
            }
            
            if(self.buffer === null)
            {
                self.buffer = data;
            }
            else
            {
                self.buffer = Buffer.concat([self.buffer, data]); // create new buffer with incoming data
            }

            while(self.parseData() === true){} // parse until false
        });


        stream.on('error', function(err){
            self.streamOpen = false;
            console.log('Error on parse', err);
        });
        stream.on('end', function(){
            self.streamOpen = false;
            console.log('Stopped parsing');

            if(self.buffer && self.buffer.length > 0)
            {
                self.startByte -= self.buffer.length;
            }

            if(self.watch === false && self.events.finished)
            {
                self.events.finished();
            }
        });
    }


    parseData()
    {
        var result = false;
        switch(this.state)
        {
            case 0: // global header
                result = this.parseGlobalFileHeader();

                // do callback if needed
                if(this.events.fileheader)
                {
                    this.events.fileheader(this.globalHeader);
                }

                // successfull parsed globale header? next state parse packet header
                if(result === true)
                {
                    this.state = 1;
                }
                break;
            case 1: // packet header
                result = this.parsePacketHeader();

                // do callback if needed
                if(this.events.packetheader)
                {
                    this.events.packetheader(this.lastPacketHeader);
                }

                // successfull parsed packet header? next state parse packet data
                if(result === true)
                {
                	this.state = 2;
                }
                break;
            case 2: // packet data

            	result = this.parsePacketData();

                // do callback if needed
                if(this.events.packetdata)
                {
                    this.events.packetdata(this.lastPacketData);
                }

                // do callback if needed
                if(this.events.packet)
                {
                    this.events.packet(this.lastPacketHeader, this.lastPacketData);
                }

                // successfull parsed packet data? next state parse packet data
                if(result === true)
                {
                	++this.packetCount;
                    this.state = 1;
                }
                break;
            default:
                throw 'Unknown PCAP-File parse state!';
        }

        return result;
    }

    parseGlobalFileHeader()
    {
        // check buffer is filled with enouth data to parse the global header
        if (this.buffer.length >= GLOBAL_HEADER_LENGTH)
        {

            // read the magic number to detect the pcap endianness
            var magicNumber = this.buffer.toString('hex', 0, 4);
            
            // determine pcap endianness
            if (magicNumber == 'a1b2c3d4')
            {
                this.endianness = 'BE';
            }
            else if (magicNumber == 'd4c3b2a1')
            {
                this.endianness = 'LE';
            }
            else
            {
                throw new Error('Can not determine the pcap endiannes, stopped parsing!');
            }


            this.globalHeader = {
                magicNumber:        this.buffer['readUInt32' + this.endianness](0, true),
                majorVersion:       this.buffer['readUInt16' + this.endianness](4, true),
                minorVersion:       this.buffer['readUInt16' + this.endianness](6, true),
                gmtOffset:          this.buffer['readInt32'  + this.endianness](8, true),
                timestampAccuracy:  this.buffer['readUInt32' + this.endianness](12, true),
                snapshotLength:     this.buffer['readUInt32' + this.endianness](16, true),
                linkLayerType:      this.buffer['readUInt32' + this.endianness](20, true)
            };

            // remove global header from buffer
            this.buffer = this.buffer.slice(GLOBAL_HEADER_LENGTH);

            return true;
        }

        return false;
    }

    parsePacketHeader()
    {
        // check buffer is filled with enouth data to parse the packet header
        if (this.buffer.length >= PACKET_HEADER_LENGTH)
        {
            this.lastPacketHeader = {
                timestampSeconds:       this.buffer['readUInt32' + this.endianness](0, true),
                timestampMicroseconds:  this.buffer['readUInt32' + this.endianness](4, true),
                capturedLength:         this.buffer['readUInt32' + this.endianness](8, true),
                originalLength:         this.buffer['readUInt32' + this.endianness](12, true)
            };

            // remove packet header from buffer
            this.buffer = this.buffer.slice(PACKET_HEADER_LENGTH);

            return true;
        }

        return false;
    }

    parsePacketData()
    {
        // check buffer is filled with enouth data to parse the packet data
        if (this.buffer.length >= this.lastPacketHeader.capturedLength)
        {
        	// check user will create hash over packet
        	let packetHash = null;
        	if(this.hash === true)
        	{
        		var data = this.buffer.slice(0, this.lastPacketHeader.capturedLength);
        		this.lastPacketHeader.hashed = sha1(data.toString());
        	}

            this.lastPacketData = {
                frameControl:     this.parseFrameControl(),
                durationId:       this.buffer['readUInt16' + this.endianness](2, true),
                sequenceControl:  this.praseSequenceControl(),
            };

            this.parseAddresses();
            this.parseFrameBody();

            this.buffer = this.buffer.slice(this.lastPacketHeader.capturedLength);

            return true;
        }

        return false;
    }

    parseFrameControl()
    {   
        var data = this.buffer['readUInt16' + this.endianness](0, true);
        var frameControl = {
            version:            (data & 0x3),
            type:               (data & 0xC)        >> 2,
            subtype:            (data & 0xF0)       >> 4,
            toDS:               (data & 0x100)      >> 8,
            fromDS:             (data & 0x200)      >> 9,
            moreFragments:      (data & 0x400)      >> 10,
            retry:              (data & 0x800)      >> 11,
            powerManagement:    (data & 0x1000)     >> 12,
            moreData:           (data & 0x2000)     >> 13,
            security:           (data & 0x4000)     >> 14,
            reserved:           (data & 0x8000)     >> 15
        };

        frameControl.typeStrings = this.typeStrings(frameControl.type, frameControl.subtype);

        return frameControl;
    }

    parseAddresses()
    {
        // is control frame?
        if(this.lastPacketData.frameControl.type === 0b01)
        {
            if(this.lastPacketData.frameControl.subtype === 0b1010)
            {
                this.lastPacketData.BSSID = this.convertStringToMac(this.buffer.toString('hex', 4, 10));
                this.lastPacketData.TA = this.convertStringToMac(this.buffer.toString('hex', 10, 16));
            }
            else if(this.lastPacketData.frameControl.subtype === 0b1011)
            {
                this.lastPacketData.RA = this.convertStringToMac(this.buffer.toString('hex', 4, 10));
                this.lastPacketData.TA = this.convertStringToMac(this.buffer.toString('hex', 10, 16));
            }
            else if(this.lastPacketData.frameControl.subtype === 0b1100)
            {
                this.lastPacketData.RA = this.convertStringToMac(this.buffer.toString('hex', 4, 10));
            }
            else if(this.lastPacketData.frameControl.subtype === 0b1101)
            {
                this.lastPacketData.RA = this.convertStringToMac(this.buffer.toString('hex', 4, 10));
            }
            else if(this.lastPacketData.frameControl.subtype === 0b1110 || this.lastPacketData.frameControl.subtype === 0b1111)
            {
                this.lastPacketData.RA = this.convertStringToMac(this.buffer.toString('hex', 4, 10));
                this.lastPacketData.BSSID = this.convertStringToMac(this.buffer.toString('hex', 10, 16));
            }
        }
        else
        {
            var addresses = {
                address1: this.buffer.toString('hex', 4, 10),
                address2: this.buffer.toString('hex', 10, 16),
                address3: this.buffer.toString('hex', 16, 22),
            };

            if(this.lastPacketData.frameControl.toDS === 1 && this.lastPacketData.frameControl.fromDS === 1)
            {
                this.lastPacketData.RA = this.convertStringToMac(addresses.address1);
                this.lastPacketData.TA = this.convertStringToMac(addresses.address2);
                this.lastPacketData.DA = this.convertStringToMac(addresses.address3);
                this.lastPacketData.SA = this.convertStringToMac(this.buffer.toString('hex', 24, 30));
            }
            else if(this.lastPacketData.frameControl.toDS === 0 && this.lastPacketData.frameControl.fromDS === 1)
            {
                this.lastPacketData.DA = this.convertStringToMac(addresses.address1);
                this.lastPacketData.BSSI = this.convertStringToMac(addresses.address2);
                this.lastPacketData.SA = this.convertStringToMac(addresses.address3);
            }
            else if(this.lastPacketData.frameControl.toDS === 1 && this.lastPacketData.frameControl.fromDS === 0)
            {
                this.lastPacketData.BSSI = this.convertStringToMac(addresses.address1);
                this.lastPacketData.SA = this.convertStringToMac(addresses.address2);
                this.lastPacketData.DA = this.convertStringToMac(addresses.address3);
            }
            else
            {
                this.lastPacketData.DA = this.convertStringToMac(addresses.address1);
                this.lastPacketData.SA = this.convertStringToMac(addresses.address2);
                this.lastPacketData.BSSI = this.convertStringToMac(addresses.address3);
            }
        }
    }

    praseSequenceControl()
    {
        var data = this.buffer['readUInt16' + this.endianness](22, true);
        return {
            fragmentNumber: (data & 0xF),
            sequenceNumber: (data & 0xFFF0) >> 4
        };
    }

    parseFrameBody()
    {
        // set frame body first
        this.lastPacketData.frameBody = {};

        // frame body time
        this.lastPacketData.frameBody.timestamp = this['convertString' + this.endianness](this.buffer.toString('hex', 24, 32));//this.buffer['readUInt' + this.endianness](24, 8, true);

        // beacon frame
        if(this.lastPacketData.frameControl.type === 0b00 && this.lastPacketData.frameControl.subtype === 0b1000)
        {
            this.lastPacketData.frameBody.beaconInterval = this.buffer['readUInt' + this.endianness](32, 2, true);

            // byte 34,2 
            this.parseCapabilityInformation();

            // parse body
            this.parseVariableFrameBody();
        }
    }

    parseCapabilityInformation()
    {
        // value
        var value = this.buffer['readUInt' + this.endianness](34, 2, true);
        this.lastPacketData.frameBody.capabilityInformation = { value: '0x'+value.toString(16) };

        // .... .... .... ...1 = ESS capabilities: Transmitter is an AP
        // .... .... .... ..0. = IBSS status: Transmitter belongs to a BSS
        // .... ..0. .... 00.. = CFP participation capabilities: No point coordinator at AP (0x0000)
        // .... .... ...1 .... = Privacy: AP/STA can support WEP
        // .... .... ..1. .... = Short Preamble: Allowed
        // .... .... .0.. .... = PBCC: Not Allowed
        // .... .... 0... .... = Channel Agility: Not in use
        // .... ...0 .... .... = Spectrum Management: Not Implemented
        // .... .1.. .... .... = Short Slot Time: In use
        // .... 0... .... .... = Automatic Power Save Delivery: Not Implemented
        // ...1 .... .... .... = Radio Measurement: Implemented
        // ..0. .... .... .... = DSSS-OFDM: Not Allowed
        // .0.. .... .... .... = Delayed Block Ack: Not Implemented
        // 0... .... .... .... = Immediate Block Ack: Not Implemented
    }

    parseVariableFrameBody()
    {
        var startIndex = 36;
        var maxLength = this.buffer.length - 4;

        this.lastPacketData.frameBody.tags = [];
        for (var i = startIndex; i < maxLength; )
        {
            var elementId = this.buffer['readUInt' + this.endianness](i, 1, true);
            var length    = this.buffer['readUInt' + this.endianness](i + 1, 1, true);
            var data      = {};

            switch(elementId)
            {
                case 0:            
                    data = this.parseSSID(i);
                    data.elementName = 'Service Set Identity (SSID)';
                    this.lastPacketData.frameBody.ssid = data.name;
                    break;
                case 1:            
                    data = this.parseSupportedRates(i);
                    data.elementName = 'Supported Rates';
                    break;
                case 3:
                    data.elementId = 3;
                    data.elementName = 'DS Parameter Set';
                    break;
                case 4:
                    data.elementId = 4;
                    data.elementName = 'CF Parameter Set';
                    break;
                case 5:
                    data.elementId = 5;
                    data.elementName = 'Traffic Indication Map (TIM)';
                    break;
                case 6:
                    data.elementId = 6;
                    data.elementName = 'IBSS Parameter Set';
                    break;
                case 7:
                    data.elementId = 7;
                    data.elementName = 'Country';
                    break;
                case 8:
                    data.elementId = 8;
                    data.elementName = 'Hopping Pattern Parameters';
                    break;
                case 9:
                    data.elementId = 9;
                    data.elementName = 'Hopping Pattern Table';
                    break;
                case 10:
                    data.elementId = 10;
                    data.elementName = 'Request';
                    break;
                case 16:
                    data.elementId = 16;
                    data.elementName = 'Challenge text';
                    break;
                case 32:
                    data.elementId = 32;
                    data.elementName = 'Power Constraint';
                    break;
                case 33:
                    data.elementId = 33;
                    data.elementName = 'Power Capability';
                    break;
                case 34:
                    data.elementId = 34;
                    data.elementName = 'Transmit Power Control (TPC) Request';
                    break;
                case 35:
                    data.elementId = 35;
                    data.elementName = 'TPC Report';
                    break;
                case 36:
                    data.elementId = 36;
                    data.elementName = 'Supported Channels';
                    break;
                case 37:
                    data.elementId = 37;
                    data.elementName = 'Channel Switch Announcement';
                    break;
                case 38:
                    data.elementId = 38;
                    data.elementName = 'Measurement Request';
                    break;
                case 39:
                    data.elementId = 39;
                    data.elementName = 'Measurement Report';
                    break;
                case 40:
                    data.elementId = 40;
                    data.elementName = 'Quiet';
                    break;
                case 41:
                    data.elementId = 41;
                    data.elementName = 'IBSS DFS';
                    break;
                case 42:
                    data.elementId = 42;
                    data.elementName = 'ERP information';
                    break;
                case 48:
                    data.elementId = 48;
                    data.elementName = 'Robust Security Network';
                    break;
                case 50:
                    data = this.parseSupportedRates(i);
                    data.elementId = 50;
                    data.elementName = 'Extended Supported Rates';
                    break;
                case 51:
                    data.elementId = 51;
                    data.elementName = 'AP Channel Report';
                    break;
                case 52:
                    data.elementId = 52;
                    data.elementName = 'Neighbor Report';
                    break;
                case 53:
                    data.elementId = 53;
                    data.elementName = 'RCPI';
                    break;
                case 54:
                    data.elementId = 54;
                    data.elementName = 'Mobility Domain (MDE)';
                    break;
                case 55:
                    data.elementId = 55;
                    data.elementName = 'Fast BSS Transition (FTE)';
                    break;
                case 56:
                    data.elementId = 56;
                    data.elementName = 'Timeout Interval';
                    break;
                case 57:
                    data.elementId = 57;
                    data.elementName = 'RIC Data (RDE)';
                    break;
                case 58:
                    data.elementId = 58;
                    data.elementName = 'DSE Registered Location';
                    break;
                case 59:
                    data.elementId = 59;
                    data.elementName = 'Supported Operating Classes';
                    break;
                case 60:
                    data.elementId = 60;
                    data.elementName = 'Extended Channel Switch Announcement';
                    break;
                case 61:
                    data.elementId = 61;
                    data.elementName = 'HT Operation';
                    break;
                case 62:
                    data.elementId = 62;
                    data.elementName = 'Secondary Channel Offset';
                    break;
                case 63:
                    data.elementId = 63;
                    data.elementName = 'BSS Average Access Delay';
                    break;
                case 64:
                    data.elementId = 64;
                    data.elementName = 'Antenna';
                    break;
                case 65:
                    data.elementId = 65;
                    data.elementName = 'RSNI';
                    break;
                case 66:
                    data.elementId = 66;
                    data.elementName = 'Measurement Pilot Transmission';
                    break;
                case 67:
                    data.elementId = 67;
                    data.elementName = 'BSS Available Admission Capacity';
                    break;
                case 68:
                    data.elementId = 68;
                    data.elementName = 'BSS AC Access Delay';
                    break;
                case 69:
                    data.elementId = 69;
                    data.elementName = 'Time Advertisement';
                    break;
                case 70:
                    data.elementId = 70;
                    data.elementName = 'RM Enabled Capabilities';
                    break;
                case 71:
                    data.elementId = 71;
                    data.elementName = 'Multiple BSSID';
                    break;
                case 72:
                    data.elementId = 72;
                    data.elementName = '20/40 BSS Coexistence';
                    break;
                case 73:
                    data.elementId = 73;
                    data.elementName = '20/40 BSS Intolerant Channel Report';
                    break;
                case 74:
                    data.elementId = 74;
                    data.elementName = 'Overlapping BSS Scan Parameters';
                    break;
                case 75:
                    data.elementId = 75;
                    data.elementName = 'RIC Descriptor';
                    break;
                case 76:
                    data.elementId = 76;
                    data.elementName = 'Management MIC';
                    break;
                case 78:
                    data.elementId = 78;
                    data.elementName = 'Event Request';
                    break;
                case 79:
                    data.elementId = 79;
                    data.elementName = 'Event Report';
                    break;
                case 80:
                    data.elementId = 80;
                    data.elementName = 'Diagnostic Request';
                    break;
                case 81:
                    data.elementId = 81;
                    data.elementName = 'Diagnostic Report';
                    break;
                case 82:
                    data.elementId = 82;
                    data.elementName = 'Location Parameters';
                    break;
                case 83:
                    data.elementId = 83;
                    data.elementName = 'Nontransmitted BSSID Capability';
                    break;
                case 84:
                    data.elementId = 84;
                    data.elementName = 'SSID List';
                    break;
                case 85:
                    data.elementId = 85;
                    data.elementName = 'Multiple BSSID-Index';
                    break;
                case 86:
                    data.elementId = 86;
                    data.elementName = 'FMS Descriptor';
                    break;
                case 87:
                    data.elementId = 87;
                    data.elementName = 'FMS Request';
                    break;
                case 88:
                    data.elementId = 88;
                    data.elementName = 'FMS Response';
                    break;
                case 89:
                    data.elementId = 89;
                    data.elementName = 'QoS Traffic Capability';
                    break;
                case 90:
                    data.elementId = 90;
                    data.elementName = 'BSS Max Idle Period';
                    break;
                case 91:
                    data.elementId = 91;
                    data.elementName = 'TFS Request';
                    break;
                case 92:
                    data.elementId = 92;
                    data.elementName = 'TFS Response';
                    break;
                case 93:
                    data.elementId = 93;
                    data.elementName = 'WNM-Sleep Mode';
                    break;
                case 94:
                    data.elementId = 94;
                    data.elementName = 'TIM Broadcast Request';
                    break;
                case 95:
                    data.elementId = 95;
                    data.elementName = 'TIM Broadcast Response';
                    break;
                case 96:
                    data.elementId = 96;
                    data.elementName = 'Collocated Interference Report';
                    break;
                case 97:
                    data.elementId = 97;
                    data.elementName = 'Channel Usage';
                    break;
                case 98:
                    data.elementId = 98;
                    data.elementName = 'Time Zone';
                    break;
                case 99:
                    data.elementId = 99;
                    data.elementName = 'DMS Request';
                    break;
                case 100:
                    data.elementId = 100;
                    data.elementName = 'DMS Response';
                    break;
                case 101:
                    data.elementId = 101;
                    data.elementName = 'Link Identifier';
                    break;
                case 102:
                    data.elementId = 102;
                    data.elementName = 'Wakeup Schedule';
                    break;
                case 104:
                    data.elementId = 104;
                    data.elementName = 'Channel Switch Timing';
                    break;
                case 105:
                    data.elementId = 105;
                    data.elementName = 'PTI Control';
                    break;
                case 106:
                    data.elementId = 106;
                    data.elementName = 'TPU Buffer Status';
                    break;
                case 107:
                    data.elementId = 107;
                    data.elementName = 'Interworking';
                    break;
                case 108:
                    data.elementId = 108;
                    data.elementName = 'Advertisement Protocol';
                    break;
                case 109:
                    data.elementId = 109;
                    data.elementName = 'Expedited Bandwidth Request';
                    break;
                case 110:
                    data.elementId = 110;
                    data.elementName = 'QoS Map Set';
                    break;
                case 111:
                    data.elementId = 111;
                    data.elementName = 'Roaming Consortium';
                    break;
                case 112:
                    data.elementId = 112;
                    data.elementName = 'Emergency Alert Identifier';
                    break;
                case 113:
                    data.elementId = 113;
                    data.elementName = 'Mesh Configuration';
                    break;
                case 114:
                    data.elementId = 114;
                    data.elementName = 'Mesh ID';
                    break;
                case 115:
                    data.elementId = 115;
                    data.elementName = 'Mesh Link Metric Report';
                    break;
                case 116:
                    data.elementId = 116;
                    data.elementName = 'Congestion Notification';
                    break;
                case 117:
                    data.elementId = 117;
                    data.elementName = 'Mesh Peering Management';
                    break;
                case 118:
                    data.elementId = 118;
                    data.elementName = 'Mesh Channel Switch Parameters';
                    break;
                case 119:
                    data.elementId = 119;
                    data.elementName = 'Mesh Awake Window';
                    break;
                case 120:
                    data.elementId = 120;
                    data.elementName = 'Beacon Timing';
                    break;
                case 121:
                    data.elementId = 121;
                    data.elementName = 'MCCAOP Setup Request';
                    break;
                case 122:
                    data.elementId = 122;
                    data.elementName = 'MCCAOP Setup Reply';
                    break;
                case 123:
                    data.elementId = 123;
                    data.elementName = 'MCCAOP Advertisement';
                    break;
                case 124:
                    data.elementId = 124;
                    data.elementName = 'MCCAOP Teardown';
                    break;
                case 125:
                    data.elementId = 125;
                    data.elementName = 'GANN';
                    break;
                case 126:
                    data.elementId = 126;
                    data.elementName = 'RANN';
                    break;
                case 127:
                    data.elementId = 127;
                    data.elementName = 'Extended Capabilities';
                    break;
                case 137:
                    data.elementId = 137;
                    data.elementName = 'PXU';
                    break;
                case 138:
                    data.elementId = 138;
                    data.elementName = 'PXUC';
                    break;
                case 139:
                    data.elementId = 139;
                    data.elementName = 'Authenticated Mesh Peering Exchange';
                    break;
                case 140:
                    data.elementId = 140;
                    data.elementName = 'MIC';
                    break;
                case 141:
                    data.elementId = 141;
                    data.elementName = 'Destination URI';
                    break;
                case 142:
                    data.elementId = 142;
                    data.elementName = 'U-APSD Coexistence';
                    break;
                case 174:
                    data.elementId = 174;
                    data.elementName = 'MCCAOP Advertisement Overview (see 8.4.2.110)';
                    break;
                case 221:
                    data.elementId = 221;
                    data.elementName = 'Vendor Specific';
                    break;

                // 11-15 Reserved; unused
                // 17-31 Reserved[a] (formerly for challenge text extension, before 802.11 shared key authentication was discontinued)
                // 43-49 Reserved
                // 128–129 Reserved
                // 133–136 Reserved
                // 143–173 Reserved
                // 175–220 Reserved
                // 222–255 Reserved
                default:
                    var value = this.buffer['readUInt' + this.endianness](i + 2 + length, length, true);

                    data.elementId = elementId;
                    data.length = length;
                    //data.data = '0x'+value.toString(16);
            }

            this.lastPacketData.frameBody.tags.push(data);

            i += length + 2;
        }
    }

    parseSSID(start)
    {
        var elementId = this.buffer['readUInt' + this.endianness](start, 1, true);
        var ssidLength = this.buffer['readUInt' + this.endianness](start + 1, 1, true);
        var ssid = this.buffer.toString('ascii', 38, 38+ssidLength);
        return { 
            elementId: elementId,
            length: ssidLength,
            name: ssid,
            elementName: 'SSID'
        };
    }

    parseSupportedRates(start)
    {
        var elementId   = this.buffer['readUInt' + this.endianness](start, 1, true);
        var length      = this.buffer['readUInt' + this.endianness](start + 1, 1, true);

        var rates = [];
        for (var i = 0; i < length; i++)
        {
            var rate = this.buffer['readUInt' + this.endianness](start + 2 + i, 1, true);
            rates.push({
                default: (0x80 & rate),
                rate: (0x7F & rate) * 0.5 // 12 * 500kbps = 6 Mbps ... result in Mbps
            });
        }

        return { 
            elementId: elementId,
            length: length,
            rates: rates,
            elementName: 'Supported Rates'
        };
    }

    typeStrings(type, subtype)
    {
        if(!this.typeTable)
        {
            this.typeTable = {};

            this.typeTable[0b00 + ''] = { name: 'Management', subtype: {}};
            this.typeTable[0b01 + ''] = { name: 'Control', subtype: {}};
            this.typeTable[0b10 + ''] = { name: 'Data', subtype: {}};
            this.typeTable[0b11 + ''] = { name: 'Reserved', subtype: {}};

            // subtype management
            this.typeTable[0b00 + ''].subtype[0b0000 + ''] = 'Association Request';
            this.typeTable[0b00 + ''].subtype[0b0001 + ''] = 'Association Response';
            this.typeTable[0b00 + ''].subtype[0b0010 + ''] = 'Reassociation Request';
            this.typeTable[0b00 + ''].subtype[0b0011 + ''] = 'Reassociation Response';
            this.typeTable[0b00 + ''].subtype[0b0100 + ''] = 'Probe Request';
            this.typeTable[0b00 + ''].subtype[0b0101 + ''] = 'Probe Response';
            this.typeTable[0b00 + ''].subtype[0b1000 + ''] = 'Beacon';
            this.typeTable[0b00 + ''].subtype[0b1001 + ''] = 'ATIM';
            this.typeTable[0b00 + ''].subtype[0b1010 + ''] = 'Dissociation';
            this.typeTable[0b00 + ''].subtype[0b1011 + ''] = 'Authentication';
            this.typeTable[0b00 + ''].subtype[0b1100 + ''] = 'Deauthentication';

            // 0100-0111 Reserved
            // 1101-1111 Reserved
            
            // subtype Control
            this.typeTable[0b01 + ''].subtype[0b1010 + ''] = 'PS-Poll';
            this.typeTable[0b01 + ''].subtype[0b1011 + ''] = 'RTS';
            this.typeTable[0b01 + ''].subtype[0b1100 + ''] = 'CTS';
            this.typeTable[0b01 + ''].subtype[0b1101 + ''] = 'ACK';
            this.typeTable[0b01 + ''].subtype[0b1110 + ''] = 'CF End';
            this.typeTable[0b01 + ''].subtype[0b1111 + ''] = 'CF End + CF ACK';
            this.typeTable[0b01 + ''].subtype[0b1010 + ''] = 'PS-Poll';
            // 0000-1001  Reserved

            // subtype Data
            this.typeTable[0b11 + ''].subtype[0b0000 + ''] = 'Data';
            this.typeTable[0b11 + ''].subtype[0b0001 + ''] = 'Data + CF ACK';
            this.typeTable[0b11 + ''].subtype[0b0010 + ''] = 'Data + CF Poll';
            this.typeTable[0b11 + ''].subtype[0b0011 + ''] = 'Data + CF ACK + CF Poll';
            this.typeTable[0b11 + ''].subtype[0b0100 + ''] = 'Null Function(No Data)';
            this.typeTable[0b11 + ''].subtype[0b0101 + ''] = 'CF ACK(no Data)';
            this.typeTable[0b11 + ''].subtype[0b0110 + ''] = 'CF Poll(no Data)';
            this.typeTable[0b11 + ''].subtype[0b0111 + ''] = 'CF ACK + CF Poll(no Data)';
        }

        return {
            type: this.typeTable[type + '']?this.typeTable[type + ''].name:'reserved/unknown',
            subtype: this.typeTable[type + ''] && this.typeTable[type + ''].subtype[subtype + '']?this.typeTable[type + ''].subtype[subtype + '']:'reserved/unknown',
        };
    }

    convertStringLE(str)
    {
        var newString = '';
        for (var i = 0; i < str.length; ++i)
        {
            newString = str[i] + str[++i] + newString;
        }

        return newString;
    }

    convertStringBE(str)
    {
        return str;
    }

    convertStringToMac(str)
    {
        var newString = '';
        for (var i = 0; i < str.length; ++i)
        {
            newString += ':' + str[i] + str[++i];
        }
        return newString.substring(1);
    }
}

module.exports = PcapParser;