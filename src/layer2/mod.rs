pub mod crc;
pub mod reader;

#[cfg(any(test, not(no_std)))]
use std::{fmt,format};
use arrayvec::ArrayVec;

/// Maximum value for the NN part of a telegram
pub const MAX_NN:usize = 16;
pub const EBUS_SYN: u8 = 0xaa;
pub const EBUS_ESCAPE: u8 = 0xa9;
pub const EBUS_ACKOK: u8 = 0x00;
pub const EBUS_ACKKO: u8 = 0xff;

#[derive(Clone)]
pub struct Packet {
    source: u8,
    destination: u8,
    primary: u8,
    secondary: u8,
    master_payload_length: u8,
    master_payload: ArrayVec<u8, MAX_NN>,
    computed_master_crc: u8,
    master_crc: u8,
    slave_payload_length: u8,
    slave_payload: ArrayVec<u8, MAX_NN>,
    computed_slave_crc: u8,
    slave_crc: u8,
}

impl Packet {
    pub fn new() -> Packet {
        Packet {
            source: 0,
            destination: 0,
            primary: 0,
            secondary: 0,
            master_payload_length: 0,
            master_payload: ArrayVec::new(),
            master_crc: 0,
            computed_master_crc: 0,
            slave_payload_length: 0,
            slave_payload: ArrayVec::new(),
            slave_crc: 0,
            computed_slave_crc: 0,
        }
    }
}

#[cfg(any(test, not(no_std)))]
impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.slave_payload_length > 0 {
            f.debug_struct("Packet")
                .field("source", &format!("{:>#04x}", &self.source))
                .field("destination", &format!("{:>#04x}", &self.destination))
                .field("primary", &format!("{:>#04x}", &self.primary))
                .field("secondary", &format!("{:>#04x}", &self.secondary))
                .field("master_payload_length", &self.master_payload_length)
                .field("master_payload", &format!("{:?}", &self.master_payload))
                .field("computed_master_crc", &format!("{:>#04x}", &self.computed_master_crc))
                .field("crc", &format!("{:>#04x}", &self.master_crc))
                .field("slave_payload_length", &self.slave_payload_length)
                .field("slave_payload", &format!("{:?}", &self.slave_payload))
                .field("computed_slave_crc", &format!("{:>#04x}", &self.computed_slave_crc))
                .field("crc_slave", &format!("{:>#04x}", &self.slave_crc))
                .finish()
        } else {
            f.debug_struct("Packet")
                .field("source", &format!("{:>#04x}", &self.source))
                .field("destination", &format!("{:>#04x}", &self.destination))
                .field("primary", &format!("{:>#04x}", &self.primary))
                .field("secondary", &format!("{:>#04x}", &self.secondary))
                .field("master_payload_length", &self.master_payload_length)
                .field("master_payload", &format!("{:?}", &self.master_payload))
                .field("computed_master_crc", &format!("{:>#04x}", &self.computed_master_crc))
                .field("crc", &format!("{:>#04x}", &self.master_crc))
                .finish()
        }
    }
}

type Nibble = u8;
/// An address is a pair (high & low) nibbles.
/// An address is a master address when its both nibbles are in `MASTER_NIBBLES`
const MASTER_NIBBLES: [Nibble; 5] = [0x00, 0x01, 0x03, 0x07, 0x0F];


#[derive(Clone,Copy,PartialEq, Eq)]
pub enum AddressClass {
    Master(Nibble),
    MasterSlave(u8),
    Slave,
    Broadcast,
    Invalid
}

impl AddressClass {
    pub fn of(c: u8) -> AddressClass {
        if c == EBUS_SYN || c == EBUS_ESCAPE { 
            return AddressClass::Invalid;
        }
        
        if c == 0xFE { 
            return AddressClass::Broadcast;
        }

        let addr: Nibble = c >> 4; // (c & 0xF0) >> 4;
        if let None = MASTER_NIBBLES.iter().position(|&n| n == addr) {
            return match AddressClass::of(c - 5) {
                AddressClass::Master(_) => AddressClass::MasterSlave(c - 5),
                _ => AddressClass::Slave
            };
        }

        let priority: Nibble = c & 0x0F;
        return match MASTER_NIBBLES.iter().position(|&n| n == priority) {
            Some(p) => AddressClass::Master(p.try_into().unwrap()),
            None => match AddressClass::of(c - 5) {
                AddressClass::Master(_) => AddressClass::MasterSlave(c - 5),
                _ => AddressClass::Slave
            }
        }
    }
}

#[cfg(any(test, not(no_std)))]
impl fmt::Debug for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressClass::Master(priority) => f.debug_struct("Master").field("priority", &format!("{:#02x}", &priority)).finish(),
            AddressClass::MasterSlave(master_addr) => f.debug_struct("MasterSlave").field("master", &format!("{:#02x}", &master_addr)).finish(),
            AddressClass::Slave => f.debug_struct("Slave").finish(),
            AddressClass::Broadcast => f.debug_struct("Broadcast").finish(),
            AddressClass::Invalid => f.debug_struct("Invalid").finish(),
        }
    }
}


#[cfg_attr(any(test, not(no_std)), derive(Debug))]
#[derive(Clone, Copy, PartialEq)]
pub enum TelegramComponent {
    SYN,
    Source,
    Destination,
    Primary,
    Secondary,
    MasterPayloadLength,
    MasterPayload,
    MasterEscapedPayload,
    MasterEscapedCRC,
    MasterCRC,
    /// SlaveACK also designate the N/ACK emited by a destination master
    SlaveACK,
    SlavePayloadLength,
    SlavePayload,
    SlaveEscapedPayload,
    SlaveEscapedCRC,
    SlaveCRC,
    MasterACK,
}
