use crate::{
    command::Command,
    error::Error,
    register::*,
    {_512K, _1M, _2M, _4M, _8M, _16M, BLOCK64_SIZE, SECTOR_SIZE},
};
use bit::BitIndex;
use embassy_futures::yield_now;
use embedded_hal::spi::Operation;
use embedded_hal_async::spi::SpiDevice;

/// Async type alias for the MX25V512 subfamily
pub type MX25V512<SPI>  = AsyncMX25V<_512K, false, SPI>;
/// Async type alias for the MX25V5126 subfamily
pub type MX25V5126<SPI> = AsyncMX25V<_512K, false, SPI>;
/// Async type alias for the MX25V512F subfamily
pub type MX25V512F<SPI> = AsyncMX25V<_512K, true, SPI>;

/// Type alias for the MX25V1006 subfamily
pub type AsyncMX25V1006<SPI> = AsyncMX25V<_1M, false, SPI>;
/// Type alias for the MX25V1035 subfamily
pub type AsyncMX25V1035<SPI> = AsyncMX25V<_1M, true, SPI>;

/// Type alias for the MX25V2006 subfamily
pub type AsyncMX25V2006<SPI> = AsyncMX25V<_2M, false, SPI>;
/// Type alias for the MX25V2035 subfamily
pub type AsyncMX25V2035<SPI> = AsyncMX25V<_2M, true, SPI>;

/// Type alias for the MX25V4006 subfamily
pub type AsyncMX25V4006<SPI> = AsyncMX25V<_4M, false, SPI>;
/// Type alias for the MX25V4035 subfamily
pub type AsyncMX25V4035<SPI> = AsyncMX25V<_4M, true, SPI>;

/// Type alias for the MX25V8006 subfamily
pub type AsyncMX25V8006<SPI> = AsyncMX25V<_8M, false, SPI>;
/// Type alias for the MX25V8035 subfamily
pub type AsyncMX25V8035<SPI> = AsyncMX25V<_8M, true, SPI>;

/// Type alias for the MX25V1606 subfamily
pub type AsyncMX25V1606<SPI> = AsyncMX25V<_16M, false, SPI>;
/// Type alias for the MX25V1635 subfamily
pub type AsyncMX25V1635<SPI> = AsyncMX25V<_16M, true, SPI>;

/// The generic low level AsyncMX25R driver
pub struct AsyncMX25V<const SIZE: u32, const QUAD: bool, SPI>
where
    SPI: SpiDevice,
{
    spi: SPI,
}

impl<const SIZE: u32, const QUAD: bool, SPI, E> AsyncMX25V<SIZE, QUAD, SPI>
where
    SPI: SpiDevice<Error = E>,
{
    pub const CAPACITY: usize = SIZE as usize + 1;

    pub fn new(spi: SPI) -> Self {
        Self { spi }
    }

    /// Read the wip bit, just less noisy than the `read_status().unwrap().wip_bit`
    pub async fn poll_wip(&mut self) -> Result<(), Error<E>> {
        if self.read_status().await?.wip_bit {
            return Err(Error::Busy);
        }
        Ok(())
    }

    pub async fn wait_wip(&mut self) -> Result<(), Error<E>> {
        loop {
            let res = self.poll_wip().await;
            match res {
                Ok(()) => return Ok(()),
                Err(Error::Busy) => yield_now().await,
                err @ Err(_) => return err,
            }
        }
    }

    pub fn verify_addr(addr: u32) -> Result<u32, Error<E>> {
        if addr > SIZE {
            return Err(Error::OutOfBounds);
        }
        Ok(addr)
    }

    async fn command_write(&mut self, bytes: &[u8]) -> Result<(), Error<E>> {
        self.spi.write(bytes).await.map_err(Error::Spi)
    }
    async fn command_transfer(&mut self, bytes: &mut [u8]) -> Result<(), Error<E>> {
        self.spi.transfer_in_place(bytes).await.map_err(Error::Spi)
    }

    async fn addr_command(&mut self, addr: u32, cmd: Command) -> Result<(), Error<E>> {
        let addr_val = Self::verify_addr(addr)?;
        let cmd: [u8; 4] = [
            cmd as u8,
            (addr_val >> 16) as u8,
            (addr_val >> 8) as u8,
            addr_val as u8,
        ];
        self.spi.write(&cmd).await.map_err(Error::Spi)
    }

    async fn write_read_base(&mut self, write: &[u8], read: &mut [u8]) -> Result<(), Error<E>> {
        self.spi
            .transaction(&mut [Operation::Write(write), Operation::Read(read)])
            .await
            .map_err(Error::Spi)
    }

    async fn read_base(
        &mut self,
        addr: u32,
        cmd: Command,
        buff: &mut [u8],
    ) -> Result<(), Error<E>> {
        self.wait_wip().await?;
        let addr_val = Self::verify_addr(addr)?;
        let cmd: [u8; 4] = [
            cmd as u8,
            (addr_val >> 16) as u8,
            (addr_val >> 8) as u8,
            addr_val as u8,
        ];

        let res = self.write_read_base(&cmd, buff).await;
        #[cfg(feature = "defmt")]
        if res.is_ok() {
            defmt::trace!("Read from {=u32}, {=usize}: {:?}", addr, buff.len(), buff);
        } else {
            defmt::trace!("Failed to read");
        }
        res
    }

    async fn read_base_dummy(
        &mut self,
        addr: u32,
        cmd: Command,
        buff: &mut [u8],
    ) -> Result<(), Error<E>> {
        let addr_val = Self::verify_addr(addr)?;
        self.wait_wip().await?;

        let cmd: [u8; 5] = [
            cmd as u8,
            (addr_val >> 16) as u8,
            (addr_val >> 8) as u8,
            addr_val as u8,
            Command::Dummy as u8,
        ];
        let res = self.write_read_base(&cmd, buff).await;
        #[cfg(feature = "defmt")]
        if res.is_ok() {
            defmt::trace!("Read from {=u32}, {=usize}: {:?}", addr, buff.len(), buff);
        } else {
            defmt::trace!("Failed to read");
        }
        res
    }

    async fn write_base(&mut self, addr: u32, cmd: Command, buff: &[u8]) -> Result<(), Error<E>> {
        let addr_val: u32 = Self::verify_addr(addr)?;
        let cmd: [u8; 4] = [
            cmd as u8,
            (addr_val >> 16) as u8,
            (addr_val >> 8) as u8,
            addr_val as u8,
        ];

        let res = self
            .spi
            .transaction(&mut [Operation::Write(&cmd), Operation::Write(buff)])
            .await
            .map_err(Error::Spi);

        #[cfg(feature = "defmt")]
        if res.is_ok() {
            defmt::trace!("write from {=u32}, {=usize}: {:?}", addr, buff.len(), buff);
        } else {
            defmt::trace!("Failed to write");
        }
        res
    }

    async fn prepare_write(&mut self) -> Result<(), Error<E>> {
        self.wait_wip().await?;
        self.write_enable().await
    }

    /// Read n bytes from an addresss, note that you should maybe use [`Self::read_fast`] instead
    pub async fn read(&mut self, addr: u32, buff: &mut [u8]) -> Result<(), Error<E>> {
        self.read_base(addr, Command::Read, buff).await
    }

    /// Read n bytes quickly from an address
    pub async fn read_fast(&mut self, addr: u32, buff: &mut [u8]) -> Result<(), Error<E>> {
        self.read_base_dummy(addr, Command::ReadF, buff).await
    }

    /// Write n bytes to a page. [`Self::write_enable`] is called internally
    pub async fn write_page(&mut self, addr: u32, buff: &[u8]) -> Result<(), Error<E>> {
        self.prepare_write().await?;
        self.write_base(addr, Command::ProgramPage, buff).await
    }

    /// Erase a 4kB sector. [`Self::write_enable`] is called internally
    pub async fn erase_sector(&mut self, addr: u32) -> Result<(), Error<E>> {
        if !addr.is_multiple_of(SECTOR_SIZE) {
            return Err(Error::NotAligned);
        }
        self.prepare_write().await?;
        self.addr_command(addr, Command::SectorErase).await?;
        #[cfg(feature = "defmt")]
        defmt::trace!("Erase sector {:?}", addr);
        Ok(())
    }

    /// Erase a 64kB block. [`Self::write_enable`] is called internally
    pub async fn erase_block64(&mut self, addr: u32) -> Result<(), Error<E>> {
        if !addr.is_multiple_of(BLOCK64_SIZE) {
            return Err(Error::NotAligned);
        }
        self.prepare_write().await?;
        self.addr_command(addr, Command::BlockErase).await?;
        #[cfg(feature = "defmt")]
        defmt::trace!("Erase block 64 {:?}", addr);
        Ok(())
    }

    /// Erase a 32kB block. [`Self::write_enable`] is called internally
    pub async fn erase_block32(&mut self, addr: u32) -> Result<(), Error<E>> {
        if !addr.is_multiple_of(SECTOR_SIZE) {
            return Err(Error::NotAligned);
        }
        self.prepare_write().await?;
        self.addr_command(addr, Command::BlockErase32).await?;
        #[cfg(feature = "defmt")]
        defmt::trace!("Erase block 32 {:?}", addr);
        Ok(())
    }

    /// Erase the whole chip. [`Self::write_enable`] is called internally
    pub async fn erase_chip(&mut self) -> Result<(), Error<E>> {
        self.prepare_write().await?;
        self.command_write(&[Command::ChipErase as u8]).await?;
        #[cfg(feature = "defmt")]
        defmt::trace!("Erase chip");
        Ok(())
    }

    /// Read using the Serial Flash Discoverable Parameter instruction
    pub async fn read_sfdp(&mut self, addr: u32, buff: &mut [u8]) -> Result<(), Error<E>> {
        self.read_base_dummy(addr, Command::ReadSfdp, buff).await
    }

    /// Enable write operation, though you shouldn't need this function since it's already handled in the write/erase operations.
    async fn write_enable(&mut self) -> Result<(), Error<E>> {
        self.command_write(&[Command::WriteEnable as u8]).await
    }

    /// Disable write
    pub async fn write_disable(&mut self) -> Result<(), Error<E>> {
        self.command_write(&[Command::WriteDisable as u8]).await
    }

    /// Read the status register
    pub async fn read_status(&mut self) -> Result<StatusRegister, Error<E>> {
        let mut command: [u8; 2] = [Command::ReadStatus as u8, 0];

        self.command_transfer(&mut command).await?;
        Ok(command[1].into())
    }

    /// Read the configuration register
    pub async fn read_configuration(&mut self) -> Result<ConfigurationRegister, Error<E>> {
        let mut command: [u8; 3] = [Command::ReadConfig as u8, 0, 0];
        self.command_transfer(&mut command).await?;
        Ok(ConfigurationRegister {
            dummmy_cycle: command[1].bit(6),
            protected_section: command[1].bit(3).into(),
            power_mode: command[2].bit(1).into(),
        })
    }

    /// Suspend the pogram erase
    pub async fn suspend_program_erase(&mut self) -> Result<(), Error<E>> {
        self.command_write(&[Command::ProgramEraseSuspend as u8])
            .await
    }

    /// Resume program erase
    pub async fn resume_program_erase(&mut self) -> Result<(), Error<E>> {
        self.command_write(&[Command::ProgramEraseResume as u8])
            .await
    }

    /// Deep powerdown the chip
    pub async fn deep_power_down(&mut self) -> Result<(), Error<E>> {
        self.command_write(&[Command::DeepPowerDown as u8]).await
    }

    /// Set the burst length
    pub async fn set_burst_length(&mut self, burst_length: u8) -> Result<(), Error<E>> {
        self.command_write(&[Command::SetBurstLength as u8, burst_length])
            .await
    }

    /// Read the identification of the device
    pub async fn read_identification(
        &mut self,
    ) -> Result<(ManufacturerId, MemoryType, MemoryDensity), Error<E>> {
        let mut command = [Command::ReadIdentification as u8, 0, 0, 0];
        self.command_transfer(&mut command).await?;
        Ok((
            ManufacturerId(command[1]),
            MemoryType(command[2]),
            MemoryDensity(command[3]),
        ))
    }

    /// Read the electronic signature of the device
    pub async fn read_electronic_id(&mut self) -> Result<ElectronicId, Error<E>> {
        let dummy = Command::Dummy as u8;
        let mut command = [Command::ReadElectronicId as u8, dummy, dummy, dummy, 0];
        self.command_transfer(&mut command).await?;
        Ok(ElectronicId(command[4]))
    }

    /// Read the manufacturer ID and the device ID
    pub async fn read_manufacturer_id(&mut self) -> Result<(ManufacturerId, DeviceId), Error<E>> {
        let dummy = Command::Dummy as u8;
        let mut command = [Command::ReadManufacturerId as u8, dummy, dummy, 0x00, 0, 0];
        self.command_transfer(&mut command).await?;
        Ok((ManufacturerId(command[4]), DeviceId(command[5])))
    }

    /// No operation, can terminate a reset enabler
    pub async fn nop(&mut self) -> Result<(), Error<E>> {
        self.command_write(&[Command::Nop as u8]).await
    }

    /// Enable reset, though you shouldn't need this function since it's already handled in the reset operation.
    pub async fn reset_enable(&mut self) -> Result<(), Error<E>> {
        self.command_write(&[Command::ResetEnable as u8]).await
    }

    /// Reset the chip. [`Self::reset_enable`] is called internally
    pub async fn reset(&mut self) -> Result<(), Error<E>> {
        self.reset_enable().await?;
        self.command_write(&[Command::ResetMemory as u8]).await
    }
}

impl<const SIZE: u32, SPI, E> AsyncMX25V<SIZE, true, SPI>
where
    SPI: SpiDevice<Error = E>,
{
    /// Write configuration to the configuration register. [`Self::write_enable`] is called internally
    pub async fn write_configuration(
        &mut self,
        block_protected: u8,
        quad_enable: bool,
        status_write_disable: bool,
        dummy_cycle: bool,
        protected_section: ProtectedArea,
    ) -> Result<(), Error<E>> {
        if block_protected > 0x0F {
            return Err(Error::Value);
        }
        self.prepare_write().await?;
        let mut command: [u8; 3] = [Command::WriteStatus as u8, 0, 0];
        command[1].set_bit_range(2..6, block_protected);
        command[1].set_bit(6, quad_enable);
        command[1].set_bit(7, status_write_disable);
        command[2].set_bit(3, protected_section.into());
        command[2].set_bit(6, dummy_cycle);
        self.command_write(&command).await?;
        Ok(())
    }
}

impl<const SIZE: u32, SPI, E> AsyncMX25V<SIZE, false, SPI>
where
    SPI: SpiDevice<Error = E>,
{
    /// Write configuration to the configuration register. [`Self::write_enable`] is called internally
    pub async fn write_configuration(
        &mut self,
        block_protected: u8,
        status_write_disable: bool,
        dummy_cycle: bool,
        protected_section: ProtectedArea,
    ) -> Result<(), Error<E>> {
        if block_protected > 0x0F {
            return Err(Error::Value);
        }
        self.prepare_write().await?;
        let mut command: [u8; 3] = [Command::WriteStatus as u8, 0, 0];
        command[1].set_bit_range(2..6, block_protected);
        command[1].set_bit(7, status_write_disable);
        command[2].set_bit(3, protected_section.into());
        command[2].set_bit(6, dummy_cycle);
        self.command_write(&command).await?;
        Ok(())
    }
}

/// Implementation of the [`NorFlash`](embedded_storage::nor_flash) trait of the  crate
mod es {

    use crate::error::Error;
    use crate::{check_erase, check_write};
    use crate::{BLOCK32_SIZE, BLOCK64_SIZE, PAGE_SIZE, SECTOR_SIZE};
    use embedded_hal_async::spi::SpiDevice;
    use embedded_storage_async::nor_flash::{MultiwriteNorFlash, NorFlash, ReadNorFlash};

    use super::AsyncMX25V;

    impl<const SIZE: u32, const QUAD: bool, SPI: SpiDevice> embedded_storage_async::nor_flash::ErrorType
        for AsyncMX25V<SIZE, QUAD, SPI>
    {
        type Error = Error<SPI::Error>;
    }

    impl<const SIZE: u32, const QUAD: bool, SPI: SpiDevice> ReadNorFlash for AsyncMX25V<SIZE, QUAD, SPI> {
        const READ_SIZE: usize = 1;

        async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
            self.read_fast(offset, bytes).await
        }

        fn capacity(&self) -> usize {
            Self::CAPACITY
        }
    }

    impl<const SIZE: u32, const QUAD: bool, SPI: SpiDevice> NorFlash for AsyncMX25V<SIZE, QUAD, SPI> {
        const WRITE_SIZE: usize = 1;
        const ERASE_SIZE: usize = SECTOR_SIZE as usize;

        async fn erase(&mut self, mut from: u32, to: u32) -> Result<(), Self::Error> {
            check_erase(self.capacity(), from, to)?;

            while from < to {
                self.wait_wip().await?;
                let addr_diff = to - from;
                if addr_diff.is_multiple_of(BLOCK64_SIZE) {
                    self.erase_block64(from).await?;
                    from += BLOCK64_SIZE;
                } else if addr_diff.is_multiple_of(BLOCK32_SIZE) {
                    self.erase_block32(from).await?;
                    from += BLOCK32_SIZE;
                } else if addr_diff.is_multiple_of(SECTOR_SIZE) {
                    self.erase_sector(from).await?;
                    from += SECTOR_SIZE;
                } else {
                    return Err(Error::NotAligned);
                }
            }
            Ok(())
        }

        async fn write(&mut self, mut offset: u32, mut bytes: &[u8]) -> Result<(), Self::Error> {
            check_write(self.capacity(), offset, bytes.len())?;

            // Write first chunk, taking into account that given addres might
            // point to a location that is not on a page boundary,
            let chunk_len = (PAGE_SIZE - (offset & 0x000000FF)) as usize;
            let mut chunk_len = chunk_len.min(bytes.len());
            self.write_page(offset, &bytes[..chunk_len]).await?;

            loop {
                bytes = &bytes[chunk_len..];
                offset += chunk_len as u32;
                chunk_len = bytes.len().min(PAGE_SIZE as usize);
                if chunk_len == 0 {
                    break;
                }
                self.write_page(offset, &bytes[..chunk_len]).await?;
            }

            Ok(())
        }
    }

    impl<const SIZE: u32, const QUAD: bool, SPI: SpiDevice> MultiwriteNorFlash for AsyncMX25V<SIZE, QUAD, SPI> {}
}
