use super::{*, crc::stack_crc};

#[inline]
/// Decode an escaped byte (which can occurs into payload or CRC)
fn escape(c: u8) -> Option<u8> {
    match c {
        0x00 => Some(EBUS_ESCAPE),
        0x01 => Some(EBUS_SYN),
        _ => None
    }
}

#[cfg_attr(any(test, not(no_std)), derive(Debug))]
pub struct BusReader {
    waiting_for: TelegramComponent,
    packet_buffer: Packet,
}

impl BusReader {
    pub fn new() -> BusReader {
        BusReader {
            packet_buffer: Packet::new(),
            waiting_for: TelegramComponent::SYN
        }
    }

    /// Drop the buffer and setup the reader for SYN-await
    fn reset(&mut self) {
        self.waiting_for = TelegramComponent::SYN;
    }

    /// Similare to `BusReader.reset()` but setup the reader for the first byte of a telegram (the source address)
    fn on_unexcepted_syn(&mut self) {
        self.reset();
        self.waiting_for = TelegramComponent::Source;
    }

    fn on_unexcepted_byte(&mut self) {
        self.reset();
    }

    fn on_master_crc(&mut self, crc: u8) {
        self.packet_buffer.master_crc = crc;

        match AddressClass::of(self.packet_buffer.destination) {
            AddressClass::Invalid => panic!("the reader state should never go futher on an protocole anomaly"),
            AddressClass::Broadcast => {
                self.waiting_for = TelegramComponent::SYN;
                self.reset();
            },
            _ => {
                self.waiting_for = TelegramComponent::SlaveACK;
            },
        }
    }

    fn on_slave_crc(&mut self, crc: u8) {
        self.packet_buffer.slave_crc = crc;
        self.waiting_for = TelegramComponent::MasterACK;
    }

    pub fn read_byte(&mut self, received: u8) {
        if received == EBUS_SYN && match self.waiting_for {
            TelegramComponent::SYN | TelegramComponent::Source => false,
            _ => true
        }{
            self.on_unexcepted_syn();
            return;
        };

        match self.waiting_for {
            TelegramComponent::SYN => {
                match received {
                    EBUS_SYN => self.waiting_for = TelegramComponent::Source,
                    _ => ()
                }
            },
            TelegramComponent::Source => {
                self.packet_buffer.source = received;
                let addr = AddressClass::of(received);
                match addr {
                    AddressClass::Master(_) => {
                        self.packet_buffer.computed_master_crc = 0x00;
                        stack_crc(&mut self.packet_buffer.computed_master_crc, received);
                        self.waiting_for = TelegramComponent::Destination;
                    },
                    AddressClass::Invalid if received == EBUS_SYN => (),
                    _ => self.on_unexcepted_byte()
                }
            },
            TelegramComponent::Destination => {
                self.packet_buffer.destination = received;
                let addr = AddressClass::of(received);
                match addr {
                    AddressClass::Invalid => self.on_unexcepted_byte(),
                    _ => {
                        stack_crc(&mut self.packet_buffer.computed_master_crc, received);
                        self.waiting_for = TelegramComponent::Primary;
                    }
                }
            },
            TelegramComponent::Primary => {
                self.packet_buffer.primary = received;
                stack_crc(&mut self.packet_buffer.computed_master_crc, received);
                self.waiting_for = TelegramComponent::Secondary;
            },
            TelegramComponent::Secondary => {
                self.packet_buffer.secondary = received;
                stack_crc(&mut self.packet_buffer.computed_master_crc, received);
                self.waiting_for = TelegramComponent::MasterPayloadLength;
            },
            TelegramComponent::MasterPayloadLength => {
                self.packet_buffer.master_payload_length = received;
                self.packet_buffer.master_payload.clear();
                stack_crc(&mut self.packet_buffer.computed_master_crc, received);

                match received {
                    0 => self.waiting_for = TelegramComponent::MasterCRC,
                    b if b as usize > MAX_NN => self.on_unexcepted_byte(),
                    _ => self.waiting_for = TelegramComponent::MasterPayload
                }
            },
            TelegramComponent::MasterPayload => {
                stack_crc(&mut self.packet_buffer.computed_master_crc, received);

                let is_escape = received == EBUS_ESCAPE;
                let has_remain = (self.packet_buffer.master_payload_length as usize).checked_sub(self.packet_buffer.master_payload.len());

                match (has_remain, is_escape) {
                    (None, _) | (Some(0), _) => panic!("Illegal state: the reader should never had a payload buffer length which exceed the announced payload length"),
                    (Some(_), true) => self.waiting_for = TelegramComponent::MasterEscapedPayload,
                    (Some(remain), false) => {
                        self.packet_buffer.master_payload.push(received);
                        self.waiting_for = if remain == 1 {
                            TelegramComponent::MasterCRC
                        } else {
                            TelegramComponent::MasterPayload
                        };
                    }
                }
            },
            TelegramComponent::MasterEscapedPayload => {
                let escaped = match escape(received) {
                    None => {
                        self.on_unexcepted_byte();
                        return;
                    },
                    Some(p) => p
                };

                let has_remain = (self.packet_buffer.master_payload_length as usize).checked_sub(self.packet_buffer.master_payload.len());
                match has_remain {
                    None | Some(0) => panic!("Illegal state: the reader should never had a payload buffer length which exceed the announced payload length"),
                    Some(remain) => {
                        stack_crc(&mut self.packet_buffer.computed_master_crc, received);
                        
                        self.packet_buffer.master_payload.push(escaped);
    
                        self.waiting_for = if remain <= 1 {
                            TelegramComponent::MasterCRC
                        } else {
                            TelegramComponent::MasterPayload
                        };
                    }
                }
            },
            TelegramComponent::MasterCRC => {
                match received {
                    EBUS_ESCAPE => self.waiting_for = TelegramComponent::MasterEscapedCRC,
                    crc => self.on_master_crc(crc),
                };
            },
            TelegramComponent::MasterEscapedCRC => {
                match escape(received) {
                    None => {
                        self.on_unexcepted_byte();
                        return;
                    },
                    Some(crc) => self.on_master_crc(crc),
                };
            },
            TelegramComponent::SlaveACK => {
                match (received, AddressClass::of(self.packet_buffer.destination)) {
                    (_, AddressClass::Invalid) | (_, AddressClass::Broadcast) => panic!("Illegal state"),
                    (EBUS_ACKOK, AddressClass::Master(_)) => {
                        self.reset();
                    },
                    (EBUS_ACKOK, AddressClass::Slave) | (EBUS_ACKOK, AddressClass::MasterSlave(_))=> {
                        self.waiting_for = TelegramComponent::SlavePayloadLength
                    },
                    (EBUS_ACKKO, _) => self.reset(),
                    (_, _) => self.on_unexcepted_byte(),
                }
            },
            TelegramComponent::SlavePayloadLength => {
                self.packet_buffer.slave_payload_length = received;
                self.packet_buffer.slave_payload.clear();
                self.packet_buffer.computed_slave_crc = 0x00;
                stack_crc(&mut self.packet_buffer.computed_slave_crc, received);

                match received {
                    0 => self.waiting_for = TelegramComponent::SlaveCRC,
                    b if b as usize > MAX_NN => self.on_unexcepted_byte(),
                    _ => self.waiting_for = TelegramComponent::SlavePayload,
                }
            },
            TelegramComponent::SlavePayload => {
                stack_crc(&mut self.packet_buffer.computed_slave_crc, received);

                let is_escape = received == EBUS_ESCAPE;
                let has_remain = (self.packet_buffer.slave_payload_length as usize).checked_sub(self.packet_buffer.slave_payload.len());

                match (has_remain, is_escape) {
                    (None, _) | (Some(0), _) => panic!("Illegal state: the reader should never had a payload buffer length which exceed the announced payload length"),
                    (Some(_), true) => self.waiting_for = TelegramComponent::SlaveEscapedPayload,
                    (Some(remain), false) => {
                        self.packet_buffer.slave_payload.push(received);
                        self.waiting_for = if remain == 1 {
                            TelegramComponent::SlaveCRC
                        } else {
                            TelegramComponent::SlavePayload
                        };
                    }
                }
            },
            TelegramComponent::SlaveEscapedPayload => {
                let escaped = match escape(received) {
                    None => {
                        self.on_unexcepted_byte();
                        return;
                    },
                    Some(p) => p
                };

                let has_remain = (self.packet_buffer.slave_payload_length as usize).checked_sub(self.packet_buffer.slave_payload.len());
                match has_remain {
                    None | Some(0) => panic!("Illegal state: the reader should never had a payload buffer length which exceed the announced payload length"),
                    Some(remain) => {
                        stack_crc(&mut self.packet_buffer.computed_slave_crc, received);
                        
                        self.packet_buffer.slave_payload.push(escaped);
    
                        self.waiting_for = if remain <= 1 {
                            TelegramComponent::SlaveCRC
                        } else {
                            TelegramComponent::SlavePayload
                        };
                    }
                }
            },
            TelegramComponent::SlaveCRC => {
                match received {
                    EBUS_ESCAPE => self.waiting_for = TelegramComponent::SlaveEscapedCRC,
                    crc => self.on_slave_crc(crc),
                };
            },
            TelegramComponent::SlaveEscapedCRC => {
                match escape(received) {
                    None => {
                        self.on_unexcepted_byte();
                        return;
                    },
                    Some(crc) => self.on_slave_crc(crc),
                };
            },
            TelegramComponent::MasterACK => {
                match received {
                    EBUS_ACKOK => {
                        self.reset();
                    },
                    EBUS_ACKKO => self.reset(),
                    _ => self.on_unexcepted_byte(),
                }
            },
        };
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_addr_is_recognized() {
        let c = AddressClass::of(0x0F);
        assert_eq!(c, AddressClass::Master(4));
    }

    #[test]
    fn master_slave_addr_is_recognized() {
        let c = AddressClass::of(0x15);
        assert_eq!(c, AddressClass::MasterSlave(0x10));
    }

    #[test]
    fn slave_addr_is_recognized() {
        let c = AddressClass::of(0x20);
        assert_eq!(c, AddressClass::Slave);
    }

    #[test]
    fn invalid_addr_is_recognized() {
        assert_eq!(AddressClass::of(EBUS_SYN), AddressClass::Invalid);
        assert_eq!(AddressClass::of(EBUS_ESCAPE), AddressClass::Invalid);
    }

    #[test]
    fn busreader_when_broadcast() {
        let mut bus_reader = BusReader::new();
        assert_eq!(bus_reader.waiting_for, TelegramComponent::SYN);

       bus_reader.read_byte(EBUS_SYN);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Source);
        bus_reader.read_byte(0xf1);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Destination);
        bus_reader.read_byte(0xfe);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::Primary);
        bus_reader.read_byte(0x08);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Secondary);
        bus_reader.read_byte(0x00);
        
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayloadLength);
        bus_reader.read_byte(0x08);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x00);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x05);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x80);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x09);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x00);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x20);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x00);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x37);
        
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterCRC);
        assert_eq!(bus_reader.packet_buffer.computed_master_crc, 0xe5);
        bus_reader.read_byte(0xe5);
        
        assert_eq!(bus_reader.waiting_for, TelegramComponent::SYN);
    }

    #[test]
    fn busreader_when_master2master() {
        let mut bus_reader = BusReader::new();
        assert_eq!(bus_reader.waiting_for, TelegramComponent::SYN);

        bus_reader.read_byte(EBUS_SYN);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Source);
        bus_reader.read_byte(0x10);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Destination);
        bus_reader.read_byte(0x03);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::Primary);
        bus_reader.read_byte(0x08);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Secondary);
        bus_reader.read_byte(0x00);
        
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayloadLength);
        bus_reader.read_byte(0x08);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x00);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x05);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x80);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x09);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x80);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x00);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x00);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x37);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterCRC);
        assert_eq!(bus_reader.packet_buffer.computed_master_crc, 0xf0);
        bus_reader.read_byte(0xf0);
        
        assert_eq!(bus_reader.waiting_for, TelegramComponent::SlaveACK);
        bus_reader.read_byte(EBUS_ACKOK);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::SYN);
    }

    #[test]
    fn bus_reader_when_escaped() {
        let mut bus_reader = BusReader::new();
        assert_eq!(bus_reader.waiting_for, TelegramComponent::SYN);

        bus_reader.read_byte(EBUS_SYN);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Source);
        bus_reader.read_byte(0x31);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Destination);
        bus_reader.read_byte(0xf6);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::Primary);
        bus_reader.read_byte(0x50);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Secondary);
        bus_reader.read_byte(0x22);
        
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayloadLength);
        bus_reader.read_byte(0x03);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(EBUS_ESCAPE);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterEscapedPayload);
        bus_reader.read_byte(0x00);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(EBUS_ESCAPE);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterEscapedPayload);
        bus_reader.read_byte(0x01);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        
        bus_reader.read_byte(0xf3);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterCRC);
        assert_eq!(bus_reader.packet_buffer.computed_master_crc, 0xa9);
        
        bus_reader.read_byte(EBUS_ESCAPE);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterEscapedCRC);
        bus_reader.read_byte(0x00);
        assert_eq!(bus_reader.packet_buffer.master_crc, EBUS_ESCAPE);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::SlaveACK);
    }

    #[test]
    fn busreader_when_master2slave() {
        // >31f6502203ec110087<0002bd0032>00
        let mut bus_reader = BusReader::new();
        assert_eq!(bus_reader.waiting_for, TelegramComponent::SYN);

        bus_reader.read_byte(EBUS_SYN);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Source);
        bus_reader.read_byte(0x31);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Destination);
        bus_reader.read_byte(0xf6);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::Primary);
        bus_reader.read_byte(0x50);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::Secondary);
        bus_reader.read_byte(0x22);
        
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayloadLength);
        bus_reader.read_byte(0x03);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0xec);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x11);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterPayload);
        bus_reader.read_byte(0x00);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterCRC);
        assert_eq!(bus_reader.packet_buffer.computed_master_crc, 0x87);
        bus_reader.read_byte(0x87);
        
        assert_eq!(bus_reader.waiting_for, TelegramComponent::SlaveACK);
        bus_reader.read_byte(EBUS_ACKOK);
        
        assert_eq!(bus_reader.waiting_for, TelegramComponent::SlavePayloadLength);
        bus_reader.read_byte(0x02);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::SlavePayload);
        bus_reader.read_byte(0xbd);
        assert_eq!(bus_reader.waiting_for, TelegramComponent::SlavePayload);
        bus_reader.read_byte(0x00);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::SlaveCRC);
        assert_eq!(bus_reader.packet_buffer.computed_slave_crc, 0x32);
        bus_reader.read_byte(0x32);
        
        assert_eq!(bus_reader.waiting_for, TelegramComponent::MasterACK);
        bus_reader.read_byte(EBUS_ACKOK);

        assert_eq!(bus_reader.waiting_for, TelegramComponent::SYN);
    }
}
