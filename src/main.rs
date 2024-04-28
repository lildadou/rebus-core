#![no_std]

#[cfg(no_std)]
extern crate core as std;

use rebus_core::layer2::reader::BusReader;
use rebus_core::layer2::*;

fn main() {
    let mut bus_reader = BusReader::new();
    
    bus_reader.read_byte(EBUS_SYN);
    bus_reader.read_byte(0x31);
    bus_reader.read_byte(0xf6);

    bus_reader.read_byte(0x50);
    bus_reader.read_byte(0x22);

    bus_reader.read_byte(0x03);

    bus_reader.read_byte(0xec);
    bus_reader.read_byte(0x11);
    bus_reader.read_byte(0x00);

    bus_reader.read_byte(0x87);

    bus_reader.read_byte(EBUS_ACKOK);

    bus_reader.read_byte(0x02);

    bus_reader.read_byte(0xbd);
    bus_reader.read_byte(0x00);

    bus_reader.read_byte(0x32);

    bus_reader.read_byte(EBUS_ACKOK);

}