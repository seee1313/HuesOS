// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
// Copyright (c) 2018-2019 Realtek Corporation
// Copyright (c) 2026 HuesOS Project
//! Complete `#![no_std]`, `#![forbid(unsafe_code)]` Realtek `RTL8821CE` (`10ec:c821`)
//! PCIe silicon bring-up, EFUSE reader, firmware IDDMA loader, PHY/RF table engine,
//! 8-queue TX / RX MPDU DMA rings, H2C/C2H command engine, and SoftAP Beacon engine.

use crate::tables::{
    RTW8821C_AGC_BTG_TYPE2_TBL, RTW8821C_AGC_TBL, RTW8821C_BB_TBL, RTW8821C_MAC_TBL,
    RTW8821C_RF_A_TBL,
};
use crate::{Rtw88FirmwareInfo, Rtw88Mmio, RtwError, RTW88_FW_HDR_LEN, RTW_TX_DESC_SIZE};

// ---------------------------------------------------------------------------
// Hardware Register Map (Realtek 8821CE / 88XX WCPU_3081)
// ---------------------------------------------------------------------------

pub const REG_SYS_FUNC_EN: u32 = 0x0002;
pub const REG_SYS_PW_CTRL: u32 = 0x0004;
pub const REG_SYS_CLK_CTRL: u32 = 0x0008;
pub const REG_RSV_CTRL: u32 = 0x001C;
pub const REG_RF_CTRL: u32 = 0x001F;
pub const REG_AFE_CTRL1: u32 = 0x0024;
pub const REG_AFE_XTAL_CTRL: u32 = 0x0024;
pub const REG_AFE_PLL_CTRL: u32 = 0x0028;
pub const REG_EFUSE_CTRL: u32 = 0x0030;
pub const REG_LDO_EFUSE_CTRL: u32 = 0x0034;
pub const REG_GPIO_MUXCFG: u32 = 0x0040;
pub const REG_LED_CFG: u32 = 0x004C;
pub const REG_PAD_CTRL1: u32 = 0x0064;
pub const REG_CTRL_TYPE: u32 = 0x0067;
pub const REG_SYS_SDIO_CTRL: u32 = 0x0070;
pub const REG_HCI_OPT_CTRL: u32 = 0x0074;
pub const REG_MCUFW_CTRL: u32 = 0x0080;
pub const REG_MCU_TST_CFG: u32 = 0x0084;
pub const RTK_PCI_HIMR0: u32 = 0x00B0;
pub const RTK_PCI_HISR0: u32 = 0x00B4;
pub const RTK_PCI_HIMR1: u32 = 0x00B8;
pub const RTK_PCI_HISR1: u32 = 0x00BC;
pub const REG_WIFI_BT_INFO: u32 = 0x00AA;
pub const REG_EFUSE_ACCESS: u32 = 0x00CF;
pub const REG_WLRF1: u32 = 0x00EC;
pub const REG_SYS_CFG1: u32 = 0x00F0;

pub const REG_CR: u32 = 0x0100;
pub const REG_TXDMA_PQ_MAP: u32 = 0x010C;
pub const REG_TRXFF_BNDY: u32 = 0x0114;
pub const REG_RXFF_BNDY: u32 = 0x011C;
pub const REG_HMETFR: u32 = 0x01CC;
pub const REG_HMEBOX0: u32 = 0x01D0;
pub const REG_HMEBOX1: u32 = 0x01D4;
pub const REG_HMEBOX2: u32 = 0x01D8;
pub const REG_HMEBOX3: u32 = 0x01DC;
pub const REG_HMEBOX0_EX: u32 = 0x01F0;
pub const REG_HMEBOX1_EX: u32 = 0x01F4;
pub const REG_HMEBOX2_EX: u32 = 0x01F8;
pub const REG_HMEBOX3_EX: u32 = 0x01FC;

pub const REG_FIFOPAGE_CTRL_2: u32 = 0x0204;
pub const REG_AUTO_LLT_V1: u32 = 0x0208;
pub const REG_TXDMA_OFFSET_CHK: u32 = 0x020C;
pub const REG_TXDMA_STATUS: u32 = 0x0210;
pub const REG_RQPN_CTRL_2: u32 = 0x022C;
pub const REG_FIFOPAGE_INFO_1: u32 = 0x0230;
pub const REG_FIFOPAGE_INFO_2: u32 = 0x0234;
pub const REG_FIFOPAGE_INFO_3: u32 = 0x0238;
pub const REG_FIFOPAGE_INFO_4: u32 = 0x023C;
pub const REG_FIFOPAGE_INFO_5: u32 = 0x0240;
pub const REG_H2C_HEAD: u32 = 0x0244;
pub const REG_H2C_TAIL: u32 = 0x0248;
pub const REG_H2C_READ_ADDR: u32 = 0x024C;
pub const REG_H2C_INFO: u32 = 0x0254;

pub const RTK_PCI_CTRL: u32 = 0x0300;
pub const RTK_PCI_TXBD_DESA_BCNQ: u32 = 0x0308;
pub const RTK_PCI_TXBD_DESA_MGMTQ: u32 = 0x0310;
pub const RTK_PCI_TXBD_DESA_VOQ: u32 = 0x0318;
pub const RTK_PCI_TXBD_DESA_VIQ: u32 = 0x0320;
pub const RTK_PCI_TXBD_DESA_BEQ: u32 = 0x0328;
pub const RTK_PCI_TXBD_DESA_BKQ: u32 = 0x0330;
pub const RTK_PCI_RXBD_DESA_MPDUQ: u32 = 0x0338;
pub const RTK_PCI_TXBD_DESA_HI0Q: u32 = 0x0340;
pub const RTK_PCI_TXBD_NUM_MGMTQ: u32 = 0x0380;
pub const RTK_PCI_RXBD_NUM_MPDUQ: u32 = 0x0382;
pub const RTK_PCI_TXBD_BCN_WORK: u32 = 0x0383;
pub const RTK_PCI_TXBD_NUM_VOQ: u32 = 0x0384;
pub const RTK_PCI_TXBD_NUM_VIQ: u32 = 0x0386;
pub const RTK_PCI_TXBD_NUM_BEQ: u32 = 0x0388;
pub const RTK_PCI_TXBD_NUM_BKQ: u32 = 0x038A;
pub const RTK_PCI_TXBD_NUM_HI0Q: u32 = 0x038C;
pub const RTK_PCI_TXBD_RWPTR_CLR: u32 = 0x039C;
pub const RTK_PCI_TXBD_IDX_VOQ: u32 = 0x03A0;
pub const RTK_PCI_TXBD_IDX_VIQ: u32 = 0x03A4;
pub const RTK_PCI_TXBD_IDX_BEQ: u32 = 0x03A8;
pub const RTK_PCI_TXBD_IDX_BKQ: u32 = 0x03AC;
pub const RTK_PCI_TXBD_IDX_MGMTQ: u32 = 0x03B0;
pub const RTK_PCI_RXBD_IDX_MPDUQ: u32 = 0x03B4;
pub const RTK_PCI_TXBD_IDX_HI0Q: u32 = 0x03B8;
pub const REG_PCIE_HRPWM1: u32 = 0x03D9;
pub const REG_DBI_WDATA_V1: u32 = 0x03E8;
pub const REG_DBI_RDATA_V1: u32 = 0x03EC;
pub const REG_DBI_FLAG_V1: u32 = 0x03F0;
pub const REG_MDIO_V1: u32 = 0x03F4;
pub const REG_PCIE_MIX_CFG: u32 = 0x03F8;

pub const REG_FWHW_TXQ_CTRL: u32 = 0x0420;
pub const REG_BCNQ_BDNY_V1: u32 = 0x0424;
pub const REG_CCK_CHECK: u32 = 0x0454;
pub const REG_AMPDU_MAX_TIME_V1: u32 = 0x0455;
pub const REG_BCNQ1_BDNY_V1: u32 = 0x0456;
pub const REG_TX_HANG_CTRL: u32 = 0x045E;
pub const REG_DATA_SC: u32 = 0x0483;
pub const REG_QUEUE_CTRL: u32 = 0x04C6;
pub const REG_PROT_MODE_CTRL: u32 = 0x04C8;
pub const REG_BAR_MODE_CTRL: u32 = 0x04CC;
pub const REG_PRECNT_CTRL: u32 = 0x04E5;

pub const REG_EDCA_VO_PARAM: u32 = 0x0500;
pub const REG_EDCA_VI_PARAM: u32 = 0x0504;
pub const REG_EDCA_BE_PARAM: u32 = 0x0508;
pub const REG_EDCA_BK_PARAM: u32 = 0x050C;
pub const REG_BCNTCFG: u32 = 0x0510;
pub const REG_PIFS: u32 = 0x0512;
pub const REG_SIFS: u32 = 0x0514;
pub const REG_SLOT: u32 = 0x051B;
pub const REG_TX_PTCL_CTRL: u32 = 0x0520;
pub const REG_TXPAUSE: u32 = 0x0522;
pub const REG_TBTT_PROHIBIT: u32 = 0x0540;
pub const REG_RD_NAV_NXT: u32 = 0x0544;
pub const REG_BCN_CTRL: u32 = 0x0550;
pub const REG_DRVERLYINT: u32 = 0x0558;
pub const REG_BCNDMATIM: u32 = 0x0559;
pub const REG_USTIME_TSF: u32 = 0x055C;
pub const REG_RXTSF_OFFSET_CCK: u32 = 0x055E;
pub const REG_TIMER0_SRC_SEL: u32 = 0x05B4;

pub const REG_TCR: u32 = 0x0604;
pub const REG_RCR: u32 = 0x0608;
pub const REG_RX_PKT_LIMIT: u32 = 0x060C;
pub const REG_RX_DRVINFO_SZ: u32 = 0x060F;
pub const REG_MACID: u32 = 0x0610;
pub const REG_BSSID: u32 = 0x0618;
pub const REG_MAR: u32 = 0x0620;
pub const REG_USTIME_EDCA: u32 = 0x0638;
pub const REG_ACKTO_CCK: u32 = 0x0639;
pub const REG_WMAC_TRXPTCL_CTL: u32 = 0x0668;
pub const REG_WMAC_TRXPTCL_CTL_H: u32 = 0x066C;
pub const RTW_SEC_CMD_REG: u32 = 0x0670;
pub const RTW_SEC_WRITE_REG: u32 = 0x0674;
pub const RTW_SEC_CONFIG: u32 = 0x0680;
pub const REG_RXFLTMAP0: u32 = 0x06A0;
pub const REG_RXFLTMAP1: u32 = 0x06A2;
pub const REG_RXFLTMAP2: u32 = 0x06A4;
pub const REG_BT_COEX_TABLE0: u32 = 0x06C0;
pub const REG_BT_COEX_TABLE1: u32 = 0x06C4;
pub const REG_BT_COEX_BRK_TABLE: u32 = 0x06C8;
pub const REG_BT_COEX_TABLE_H: u32 = 0x06CC;
pub const RTK_PCIE_LINK_CFG: u16 = 0x0719;
pub const REG_BT_COEX_V2: u32 = 0x0762;
pub const REG_BT_STAT_CTRL: u32 = 0x0778;
pub const REG_BT_TDMA_TIME: u32 = 0x0790;
pub const REG_WMAC_OPTION_FUNCTION: u32 = 0x07D0;

// 8821C BB / RF registers (exact `rtw8821c.h` + `reg.h` silicon offsets)
pub const REG_SYS_CTRL: u32 = 0x0000;
pub const REG_INIRTS_RATE_SEL: u32 = 0x0480;
pub const REG_SND_PTCL_CTRL: u32 = 0x0718;
pub const REG_RXPSEL: u32 = 0x0808;
pub const REG_RXCCAMSK: u32 = 0x0814;
pub const REG_CLKTRK: u32 = 0x0860;
pub const REG_ADCCLK: u32 = 0x08AC;
pub const REG_ADC160: u32 = 0x08C4;
pub const REG_ADC40: u32 = 0x08C8;
pub const REG_CHFIR: u32 = 0x08F0;
pub const REG_ACBB0: u32 = 0x0948;
pub const REG_ACBBRXFIR: u32 = 0x094C;
pub const REG_RXSB: u32 = 0x0A00;
pub const REG_PWRTH: u32 = 0x0A08;
pub const REG_CCA_FLTR: u32 = 0x0A20;
pub const REG_TXSF2: u32 = 0x0A24;
pub const REG_TXSF6: u32 = 0x0A28;
pub const REG_CCK0_FAREPORT: u32 = 0x0A2C;
pub const REG_ENTXCCK: u32 = 0x0A80;
pub const REG_ENRXCCA: u32 = 0x0A84;
pub const REG_PWRTH2: u32 = 0x0AA8;
pub const REG_CSRATIO: u32 = 0x0AAA;
pub const REG_TXFILTER: u32 = 0x0AAC;
pub const REG_TXSCALE_A: u32 = 0x0C1C;
pub const REG_TXDFIR: u32 = 0x0C20;
pub const REG_RXIGI_A: u32 = 0x0C50;
pub const REG_LSSI_WRITE_A: u32 = 0x0C90;
pub const REG_RFE_CTRL8: u32 = 0x0CB4;
pub const REG_RFECTL: u32 = 0x0CB8;
pub const REG_TXAGC_A_BASE: u32 = 0x1D00;
pub const RTK_PCI_HIMR3: u32 = 0x10B8;
pub const RTK_PCI_HISR3: u32 = 0x10BC;
pub const REG_CPU_DMEM_CON: u32 = 0x1080;
pub const REG_H2C_PKT_READADDR: u32 = 0x10D0;
pub const REG_H2C_PKT_WRITEADDR: u32 = 0x10D4;
pub const REG_FW_DBG7: u32 = 0x10FC;
pub const REG_CR_EXT: u32 = 0x1100;
pub const REG_DDMA_CH0SA: u32 = 0x1200;
pub const REG_DDMA_CH0DA: u32 = 0x1204;
pub const REG_DDMA_CH0CTRL: u32 = 0x1208;
pub const RTK_PCI_TXBD_DESA_H2CQ: u32 = 0x1320;
pub const RTK_PCI_TXBD_NUM_H2CQ: u32 = 0x1328;
pub const RTK_PCI_TXBD_IDX_H2CQ: u32 = 0x132C;
pub const RTK_PCI_TXBD_H2CQ_CSR: u32 = 0x1330;
pub const REG_H2CQ_CSR: u32 = 0x1330;
pub const REG_FAST_EDCA_VOVI_SETTING: u32 = 0x1448;
pub const REG_FAST_EDCA_BEBK_SETTING: u32 = 0x144C;
pub const REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1: u32 = 0x1700;
pub const REG_WL2LTECOEX_INDIRECT_ACCESS_WRITE_DATA_V1: u32 = 0x1704;
pub const REG_WL2LTECOEX_INDIRECT_ACCESS_READ_DATA_V1: u32 = 0x1708;
pub const LTECOEX_READY: u32 = 1 << 29;
pub const LTE_COEX_CTRL: u16 = 0x0038;
pub const REG_DMEM_CTRL: u32 = 0x1080;
pub const RF_BASE_ADDR_A: u32 = 0x2800;

// RF Path-A registers
pub const RF_DTXLOK: u32 = 0x08;
pub const RF_CFGCH: u32 = 0x18;
pub const RF_LUTWA: u32 = 0x33;
pub const RF_LUTWD0: u32 = 0x3F;
pub const RF_XTALX2: u32 = 0xB8;
pub const RF_LUTDBG: u32 = 0xDF;
pub const RF_LUTWE2: u32 = 0xEE;
pub const RFREG_MASK: u32 = 0xFFFFF;

// Firmware & FIFO memory layout
pub const OCPBASE_TXBUF_88XX: u32 = 0x1878_0000;
pub const OCPBASE_DMEM_88XX: u32 = 0x0020_0000;
pub const FW_HDR_CHKSUM_SIZE: u32 = 8;
pub const TX_PAGE_SIZE: u32 = 128;
pub const TX_PAGE_SIZE_SHIFT: u32 = 7;
pub const RTL8821C_TXFF_SIZE: u32 = 65_536;
pub const RTL8821C_RXFF_SIZE: u32 = 16_384;
pub const C2H_PKT_BUF: u32 = 256;
pub const PHY_STATUS_SIZE: u8 = 4;

// Hardware descriptor rates
pub const DESC_RATE1M: u8 = 0x00;
pub const DESC_RATE6M: u8 = 0x04;
pub const DESC_RATE24M: u8 = 0x08;
pub const DESC_RATE54M: u8 = 0x0B;
pub const DESC_RATEMCS7: u8 = 0x13;
pub const DESC_RATEVHT1SS_MCS7: u8 = 0x33;

// Hardware TX queue indices matching Realtek `enum rtw_tx_queue_type`
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum RtwTxQueue {
    Bk = 0,
    Be = 1,
    Vi = 2,
    Vo = 3,
    Bcn = 4,
    Mgmt = 5,
    Hi0 = 6,
    H2c = 7,
}

pub const RTK_MAX_TX_QUEUE_NUM: usize = 8;
pub const RTW_PCI_TX_BD_SIZE: usize = 16; // 2x 8-byte scatter-gather BDs
pub const RTW_PCI_RX_BD_SIZE: usize = 8;
pub const RTK_PCI_RX_BUF_SIZE: usize = 11_478; // 11454 + 24
pub const RTW_DMA_RX_STRIDE: usize = 12_288; // 4 KiB-aligned >= RTK_PCI_RX_BUF_SIZE
pub const RTW_DMA_TX_STRIDE: usize = 2_048;
pub const RTW_RX_RING_LEN: usize = 128;

// Ring capacities (must fit comfortably in 4 MiB DMA slice)
pub const TX_RING_CAP: [usize; RTK_MAX_TX_QUEUE_NUM] = [
    64,  // BK
    128, // BE
    64,  // VI
    64,  // VO
    2,   // BCN (rsvd page / beacon)
    64,  // MGMT
    32,  // HI0
    32,  // H2C
];

const TX_QUEUE_IDX_REG: [u32; RTK_MAX_TX_QUEUE_NUM] = [
    RTK_PCI_TXBD_IDX_BKQ,
    RTK_PCI_TXBD_IDX_BEQ,
    RTK_PCI_TXBD_IDX_VIQ,
    RTK_PCI_TXBD_IDX_VOQ,
    0, // BCN uses RTK_PCI_TXBD_BCN_WORK
    RTK_PCI_TXBD_IDX_MGMTQ,
    RTK_PCI_TXBD_IDX_HI0Q,
    RTK_PCI_TXBD_IDX_H2CQ,
];

const TX_QUEUE_QSEL: [u8; RTK_MAX_TX_QUEUE_NUM] = [
    1,  // BK -> TID1
    0,  // BE -> TID0
    5,  // VI -> TID5
    6,  // VO -> TID6
    16, // BCN -> TX_DESC_QSEL_BEACON
    18, // MGMT -> TX_DESC_QSEL_MGMT
    17, // HI0 -> TX_DESC_QSEL_HIGH
    19, // H2C -> TX_DESC_QSEL_H2C
];

/// Abstract DMA memory window (< 4 GiB physical address space) backing PCIe rings.
pub trait Rtw88Dma {
    fn phys_base(&self) -> u32;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn read_bytes(&self, offset: usize, dst: &mut [u8]);
    fn write_bytes(&mut self, offset: usize, src: &[u8]);
    fn zero_range(&mut self, offset: usize, len: usize) {
        let z = [0u8; 64];
        let mut cur = offset;
        let end = offset.saturating_add(len);
        while cur < end {
            let n = (end - cur).min(z.len());
            self.write_bytes(cur, &z[..n]);
            cur += n;
        }
    }
}

/// Decoded factory EFUSE contents for `RTL8821CE`.
#[derive(Clone, Copy, Debug)]
pub struct Rtw8821cEfuseInfo {
    pub mac_addr: [u8; 6],
    pub rfe_option: u8,
    pub rfe_btg: bool,
    pub pkg_type: u8,
    pub crystal_cap: u8,
    pub thermal_meter: u8,
    pub tx_bb_swing_2g: u8,
    pub tx_bb_swing_5g: u8,
    pub txpwr_2g_cck: [u8; 6],
    pub txpwr_2g_bw40: [u8; 5],
    pub txpwr_5g_bw40: [u8; 14],
    pub country_code: [u8; 2],
    pub efuse_valid: bool,
}

impl Default for Rtw8821cEfuseInfo {
    fn default() -> Self {
        Self {
            mac_addr: [0x00, 0xE0, 0x4C, 0x88, 0x21, 0xCE],
            rfe_option: 0,
            rfe_btg: false,
            pkg_type: 0,
            crystal_cap: 0x20,
            thermal_meter: 0x1A,
            tx_bb_swing_2g: 0,
            tx_bb_swing_5g: 0,
            txpwr_2g_cck: [0x28; 6],
            txpwr_2g_bw40: [0x28; 5],
            txpwr_5g_bw40: [0x28; 14],
            country_code: *b"00",
            efuse_valid: false,
        }
    }
}

/// Decoded C2H event delivered by the `RTL8821CE` MCU over the RX ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtwC2hEvent {
    RaReport {
        mac_id: u8,
        rate: u8,
        sgi: bool,
        bw: u8,
    },
    TxReport {
        seq_num: u8,
        ok: bool,
    },
    Other {
        cmd_id: u8,
        seq: u8,
    },
}

#[derive(Clone, Copy, Default)]
struct TxRingMeta {
    bd_off: usize,
    buf_off: usize,
    buf_stride: usize,
    cap: usize,
    wp: u16,
    rp: u16,
}

#[derive(Clone, Copy, Default)]
struct RxRingMeta {
    bd_off: usize,
    buf_off: usize,
    cap: usize,
    rp: u16,
    rx_tag: u16,
}

#[derive(Clone, Copy, Default)]
pub struct FifoLayout {
    pub txff_pg_num: u16,
    pub rsvd_pg_num: u16,
    pub acq_pg_num: u16,
    pub rsvd_boundary: u16,
    pub rsvd_drv_addr: u16,
    pub rsvd_h2c_info_addr: u16,
    pub rsvd_h2c_sta_info_addr: u16,
    pub rsvd_h2cq_addr: u16,
    pub rsvd_fw_txbuf_addr: u16,
}

impl FifoLayout {
    fn compute_8821c() -> Self {
        let txff_pg_num = (RTL8821C_TXFF_SIZE / TX_PAGE_SIZE) as u16; // 512
        let rsvd_drv_pg_num = 8u16;
        let rsvd_h2c_extrainfo = 24u16;
        let rsvd_h2c_staticinfo = 8u16;
        let rsvd_h2cq = 8u16;
        let rsvd_fw_txbuf = 4u16;
        let rsvd_pg_num =
            rsvd_drv_pg_num + rsvd_h2c_extrainfo + rsvd_h2c_staticinfo + rsvd_h2cq + rsvd_fw_txbuf; // 52
        let acq_pg_num = txff_pg_num - rsvd_pg_num; // 460
        let rsvd_boundary = acq_pg_num;
        let mut cur = txff_pg_num;
        cur -= rsvd_fw_txbuf;
        let rsvd_fw_txbuf_addr = cur;
        cur -= rsvd_h2cq;
        let rsvd_h2cq_addr = cur;
        cur -= rsvd_h2c_staticinfo;
        let rsvd_h2c_sta_info_addr = cur;
        cur -= rsvd_h2c_extrainfo;
        let rsvd_h2c_info_addr = cur;
        cur -= rsvd_drv_pg_num;
        let rsvd_drv_addr = cur;
        Self {
            txff_pg_num,
            rsvd_pg_num,
            acq_pg_num,
            rsvd_boundary,
            rsvd_drv_addr,
            rsvd_h2c_info_addr,
            rsvd_h2c_sta_info_addr,
            rsvd_h2cq_addr,
            rsvd_fw_txbuf_addr,
        }
    }
}

/// Complete Realtek `RTL8821CE` PCIe hardware controller state.
pub struct Rtl8821ceHw {
    tx_rings: [TxRingMeta; RTK_MAX_TX_QUEUE_NUM],
    rx_ring: RxRingMeta,
    pub fifo: FifoLayout,
    pub efuse: Rtw8821cEfuseInfo,
    pub fw_info: Option<Rtw88FirmwareInfo>,
    pub cut_version: u8,
    pub current_channel: u8,
    pub current_bw_mhz: u8,
    ch_param: [u32; 3],
    cck_pd_default: u8,
    h2c_seq: u16,
    h2c_mbox: u8,
    tx_seq: u16,
    pub last_diag: u8,
    pub last_mcufw_ctrl: u16,
    pub initialized: bool,
}

impl Rtl8821ceHw {
    /// Minimum DMA window size required for all 8 TX rings + 128-entry RX ring.
    pub const MIN_DMA_BYTES: usize = 0x2A_0000; // 2.625 MiB (< 4 MiB grant)

    pub fn new() -> Self {
        let mut cur = 0usize;
        let mut tx_rings = [TxRingMeta::default(); RTK_MAX_TX_QUEUE_NUM];
        for q in 0..RTK_MAX_TX_QUEUE_NUM {
            cur = (cur + 0xFF) & !0xFF;
            let bd_off = cur;
            cur += TX_RING_CAP[q] * RTW_PCI_TX_BD_SIZE;
            tx_rings[q] = TxRingMeta {
                bd_off,
                buf_off: 0,
                buf_stride: if q == RtwTxQueue::Bcn as usize {
                    8192
                } else {
                    RTW_DMA_TX_STRIDE
                },
                cap: TX_RING_CAP[q],
                wp: 0,
                rp: 0,
            };
        }
        cur = (cur + 0xFF) & !0xFF;
        let rx_bd_off = cur;
        cur += RTW_RX_RING_LEN * RTW_PCI_RX_BD_SIZE;

        for ring in &mut tx_rings {
            cur = (cur + 0xFF) & !0xFF;
            ring.buf_off = cur;
            cur += ring.cap * ring.buf_stride;
        }
        cur = (cur + 0xFFF) & !0xFFF;
        let rx_buf_off = cur;

        Self {
            tx_rings,
            rx_ring: RxRingMeta {
                bd_off: rx_bd_off,
                buf_off: rx_buf_off,
                cap: RTW_RX_RING_LEN,
                rp: 0,
                rx_tag: 0,
            },
            fifo: FifoLayout::compute_8821c(),
            efuse: Rtw8821cEfuseInfo::default(),
            fw_info: None,
            cut_version: 0,
            current_channel: 1,
            current_bw_mhz: 20,
            ch_param: [0; 3],
            cck_pd_default: 0,
            h2c_seq: 0,
            h2c_mbox: 0,
            tx_seq: 1,
            last_diag: 0,
            last_mcufw_ctrl: 0,
            initialized: false,
        }
    }

    /// Execute full Realtek `RTL8821CE` bring-up on real PCIe BAR2 + `< 4 GiB` DMA.
    pub fn init_hardware<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
        fw_blob: &[u8],
    ) -> Result<(), RtwError> {
        self.initialized = false;
        self.last_diag = 0;
        self.last_mcufw_ctrl = 0;
        let res = self.init_hardware_inner(mmio, dma, fw_blob);
        self.last_mcufw_ctrl = mmio.read16(REG_MCUFW_CTRL);
        if let Err(err) = res {
            self.last_diag = err.diag_code();
            return Err(err);
        }
        Ok(())
    }

    fn init_hardware_inner<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
        fw_blob: &[u8],
    ) -> Result<(), RtwError> {
        if dma.len() < Self::MIN_DMA_BYTES {
            return Err(RtwError::MalformedDescriptor);
        }
        let fw_info = Rtw88FirmwareInfo::parse(fw_blob)?;
        self.fw_info = Some(fw_info);

        // 1. Read silicon cut version from REG_SYS_CFG1
        let sys_cfg1 = mmio.read32(REG_SYS_CFG1);
        if sys_cfg1 == 0xFFFF_FFFF {
            return Err(RtwError::MmioUnreachable);
        }
        self.cut_version = ((sys_cfg1 >> 12) & 0x0F) as u8;

        // 2. Disable interrupts during bring-up & configure PCIe MDIO/ASPM
        mmio.write32(RTK_PCI_HIMR0, 0);
        mmio.write32(RTK_PCI_HIMR1, 0);
        mmio.write32(RTK_PCI_HIMR3, 0);
        self.pci_phy_and_aspm_cfg(mmio);

        // 3. Initialize & program all 8 TX rings + 1 RX MPDU ring (`rtw_hci_setup`)
        self.setup_pci_rings(mmio, dma);

        // 4. Power on MAC (`rtw_mac_power_on`: pre_system_cfg + pwr_seq + init_system_cfg)
        self.mac_power_on(mmio)?;

        // 5. Read physical 512B EFUSE -> logical 512B EFUSE -> factory MAC & RF cal
        self.read_efuse(mmio);
        self.program_mac_addr(mmio, &self.efuse.mac_addr);

        // 6. Re-assert PCIe ring control after `card_enable_flow_8821c` zeroes 0x0300..0x0301
        self.setup_pci_rings(mmio, dma);

        // 7. Download `rtw8821c_fw.bin` (DMEM + IMEM + EMEM) via BCNQ + IDDMA & boot WCPU
        //    (`rtw_power_on` runs `rtw_download_firmware` BEFORE `rtw_mac_init`)
        self.download_firmware(mmio, dma, fw_blob, &fw_info)?;

        // 8. Reset PCIe rings after firmware boot (`rtw_hci_setup` in `__rtw_download_firmware`)
        //    & configure TRXFF / Auto-LLT / H2C / WMAC (`rtw_mac_init`)
        self.setup_pci_rings(mmio, dma);
        self.init_trx_cfg(mmio)?;
        self.mac_init_8821c(mmio);
        self.drv_info_cfg(mmio);

        // 9. Power up BB/RF, load authentic 8821C MAC/BB/AGC/RF tables, set XTAL & PTA/Coex
        self.phy_set_param_8821c(mmio);
        self.coex_init_hw_config_8821c(mmio);

        // 10. Enable hardware AES-CCMP security engine & RX filter (`rtwdev->hal.rcr`).
        //     On 8821C (WCPU_3081), frame-type acceptance is controlled by `REG_RXFLTMAP0/1/2`
        //     (`0xFFFF / 0x0FFF / 0xFFFF`), while `BIT(11)` of `REG_RCR` is `BIT_TA_BCN`
        //     (which drops Beacons from non-associated BSSIDs if set!). Match Linux `rtw88`
        //     `0xF410_400E` with `BIT_CBSSID_BCN | BIT_CBSSID_DATA` cleared so all Beacons,
        //     Probe Responses, Auth/Assoc, and Data frames pass cleanly.
        self.enable_sec_engine(mmio);
        let rcr = (1u32 << 31) // BIT_APP_FCS
            | (1u32 << 30) // BIT_APP_MIC
            | (1u32 << 29) // BIT_APP_ICV
            | (1u32 << 28) // BIT_APP_PHYSTS
            | (1u32 << 26) // BIT_VHT_DACK
            | (1u32 << 20) // BIT_PKTCTL_DLEN
            | (1u32 << 14) // BIT_HTC_LOC_CTRL
            | (1u32 << 3)  // BIT_AB (Broadcast)
            | (1u32 << 2)  // BIT_AM (Multicast)
            | (1u32 << 1); // BIT_APM (Unicast match)
        mmio.write32(REG_RCR, rcr);
        mmio.write32(REG_MAR, 0xFFFF_FFFF);
        mmio.write32(REG_MAR + 4, 0xFFFF_FFFF);

        // 11. Unmask HISR status bits (`rtw_pci_start`)
        let imr0 = (1u32 << 7)  // HIGHDOK
            | (1u32 << 6)  // MGNTDOK
            | (1u32 << 5)  // BKDOK
            | (1u32 << 4)  // BEDOK
            | (1u32 << 3)  // VIDOK
            | (1u32 << 2)  // VODOK
            | (1u32 << 0)  // ROK
            | (1u32 << 14) // BCNDMAINT_E
            | (1u32 << 10); // C2HCMD
        mmio.write32(RTK_PCI_HISR0, 0xFFFF_FFFF);
        mmio.write32(RTK_PCI_HISR1, 0xFFFF_FFFF);
        mmio.write32(RTK_PCI_HISR3, 0xFFFF_FFFF);
        mmio.write32(RTK_PCI_HIMR0, imr0);
        mmio.write32(RTK_PCI_HIMR1, 1u32 << 9); // TXFOVW
        mmio.write32(RTK_PCI_HIMR3, 1u32 << 16); // H2CDOK

        // 12. Send initial firmware H2C packets (GENERAL_INFO + PHYDM_INFO), tune ch 1 & IQK
        let _ = self.send_fw_general_info(mmio, dma);
        let _ = self.send_fw_phydm_info(mmio, dma);
        self.set_channel(mmio, 1, 20);
        self.trigger_iqk(mmio, dma);

        self.initialized = true;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // PCIe MDIO / DBI & Ring Initialization
    // -----------------------------------------------------------------------

    fn dbi_write8<M: Rtw88Mmio>(&self, mmio: &mut M, addr: u16, data: u8) {
        let rem = addr & 0x3;
        let write_addr = (addr & 0x0FFC) | ((1u16 << rem) << 12);
        mmio.write8(REG_DBI_WDATA_V1 + u32::from(rem), data);
        mmio.write16(REG_DBI_FLAG_V1, write_addr);
        mmio.write8(REG_DBI_FLAG_V1 + 2, 0x01); // BIT_DBI_WFLAG >> 16
        for _ in 0..20 {
            if mmio.read8(REG_DBI_FLAG_V1 + 2) == 0 {
                return;
            }
            mmio.delay_us(10);
        }
    }

    fn dbi_read8<M: Rtw88Mmio>(&self, mmio: &mut M, addr: u16) -> Option<u8> {
        let read_addr = addr & 0x0FFC;
        mmio.write16(REG_DBI_FLAG_V1, read_addr);
        mmio.write8(REG_DBI_FLAG_V1 + 2, 0x02); // BIT_DBI_RFLAG >> 16
        for _ in 0..20 {
            if mmio.read8(REG_DBI_FLAG_V1 + 2) == 0 {
                return Some(mmio.read8(REG_DBI_RDATA_V1 + u32::from(addr & 3)));
            }
            mmio.delay_us(10);
        }
        None
    }

    fn mdio_write<M: Rtw88Mmio>(&self, mmio: &mut M, addr: u8, data: u16, gen1: bool) {
        mmio.write16(REG_MDIO_V1, data);
        let mut page = if addr < 0x20 { 0u8 } else { 1u8 };
        page += if gen1 { 0 } else { 2 };
        mmio.write8(REG_PCIE_MIX_CFG, addr & 0x1F);
        mmio.write8(REG_PCIE_MIX_CFG + 3, page);
        let v = mmio.read32(REG_PCIE_MIX_CFG) | (1u32 << 5);
        mmio.write32(REG_PCIE_MIX_CFG, v);
        for _ in 0..20 {
            if (mmio.read32(REG_PCIE_MIX_CFG) & (1u32 << 5)) == 0 {
                return;
            }
            mmio.delay_us(10);
        }
    }

    fn pci_phy_and_aspm_cfg<M: Rtw88Mmio>(&self, mmio: &mut M) {
        // pcie_gen1_param_8821c: { offset = 0x0009, value = 0x6380, IP_SEL_PHY }
        self.mdio_write(mmio, 0x09, 0x6380, true);
        // Disable ASPM L1 & CLKREQ SW gating during active DMA so link never drops
        if let Some(mut v) = self.dbi_read8(mmio, RTK_PCIE_LINK_CFG) {
            v &= !((1u8 << 3) | (1u8 << 4));
            self.dbi_write8(mmio, RTK_PCIE_LINK_CFG, v);
        }
    }

    fn setup_pci_rings<M: Rtw88Mmio, D: Rtw88Dma>(&mut self, mmio: &mut M, dma: &mut D) {
        let base_pa = dma.phys_base();

        for ring in &mut self.tx_rings {
            dma.zero_range(ring.bd_off, ring.cap * RTW_PCI_TX_BD_SIZE);
            ring.wp = 0;
            ring.rp = 0;
        }

        // Populate RX buffer descriptors (`buf_size = 11478`, `dma = slot_pa`)
        for idx in 0..self.rx_ring.cap {
            let buf_pa =
                base_pa.wrapping_add((self.rx_ring.buf_off + idx * RTW_DMA_RX_STRIDE) as u32);
            let mut rbd = [0u8; RTW_PCI_RX_BD_SIZE];
            rbd[0..2].copy_from_slice(&(RTK_PCI_RX_BUF_SIZE as u16).to_le_bytes());
            rbd[2..4].copy_from_slice(&0u16.to_le_bytes());
            rbd[4..8].copy_from_slice(&buf_pa.to_le_bytes());
            dma.write_bytes(self.rx_ring.bd_off + idx * RTW_PCI_RX_BD_SIZE, &rbd);
        }
        self.rx_ring.rp = 0;
        self.rx_ring.rx_tag = 0;

        let tmp = mmio.read8(RTK_PCI_CTRL + 3);
        mmio.write8(RTK_PCI_CTRL + 3, tmp | 0xF7);

        mmio.write32(
            RTK_PCI_TXBD_DESA_BCNQ,
            base_pa.wrapping_add(self.tx_rings[RtwTxQueue::Bcn as usize].bd_off as u32),
        );
        mmio.write32(RTK_PCI_TXBD_DESA_BCNQ + 4, 0);

        let h2c = &self.tx_rings[RtwTxQueue::H2c as usize];
        mmio.write16(RTK_PCI_TXBD_NUM_H2CQ, (h2c.cap as u16) & 0x0FFF);
        mmio.write32(
            RTK_PCI_TXBD_DESA_H2CQ,
            base_pa.wrapping_add(h2c.bd_off as u32),
        );
        mmio.write32(RTK_PCI_TXBD_DESA_H2CQ + 4, 0);

        let ring_regs = [
            (RtwTxQueue::Bk, RTK_PCI_TXBD_NUM_BKQ, RTK_PCI_TXBD_DESA_BKQ),
            (RtwTxQueue::Be, RTK_PCI_TXBD_NUM_BEQ, RTK_PCI_TXBD_DESA_BEQ),
            (RtwTxQueue::Vo, RTK_PCI_TXBD_NUM_VOQ, RTK_PCI_TXBD_DESA_VOQ),
            (RtwTxQueue::Vi, RTK_PCI_TXBD_NUM_VIQ, RTK_PCI_TXBD_DESA_VIQ),
            (
                RtwTxQueue::Mgmt,
                RTK_PCI_TXBD_NUM_MGMTQ,
                RTK_PCI_TXBD_DESA_MGMTQ,
            ),
            (
                RtwTxQueue::Hi0,
                RTK_PCI_TXBD_NUM_HI0Q,
                RTK_PCI_TXBD_DESA_HI0Q,
            ),
        ];
        for (q, num_reg, desa_reg) in ring_regs {
            let r = &self.tx_rings[q as usize];
            mmio.write16(num_reg, (r.cap as u16) & 0x0FFF);
            mmio.write32(desa_reg, base_pa.wrapping_add(r.bd_off as u32));
            mmio.write32(desa_reg + 4, 0);
        }

        mmio.write16(RTK_PCI_RXBD_NUM_MPDUQ, (self.rx_ring.cap as u16) & 0x0FFF);
        mmio.write32(
            RTK_PCI_RXBD_DESA_MPDUQ,
            base_pa.wrapping_add(self.rx_ring.bd_off as u32),
        );
        mmio.write32(RTK_PCI_RXBD_DESA_MPDUQ + 4, 0);

        mmio.write32(RTK_PCI_TXBD_RWPTR_CLR, 0xFFFF_FFFF);
        let h2c_csr = mmio.read32(RTK_PCI_TXBD_H2CQ_CSR);
        mmio.write32(RTK_PCI_TXBD_H2CQ_CSR, h2c_csr | (1u32 << 16) | (1u32 << 8));

        // Reset DMA interface & enable RX tag tracking (`rtw_pci_dma_reset`)
        let pci_ctrl = mmio.read32(RTK_PCI_CTRL);
        mmio.write32(RTK_PCI_CTRL, pci_ctrl | (1u32 << 20) | (1u32 << 15));
    }

    // -----------------------------------------------------------------------
    // Power-On Sequence (`card_enable_flow_8821c`)
    // -----------------------------------------------------------------------

    fn pwr_poll<M: Rtw88Mmio>(&self, mmio: &mut M, addr: u32, mask: u8, target: u8) -> bool {
        let want = target & mask;
        for _ in 0..5_000 {
            if (mmio.read8(addr) & mask) == want {
                return true;
            }
            mmio.delay_us(20);
        }
        // Realtek PCIe fallback: toggle BIT_PFM_WOWL and re-poll
        let v = mmio.read8(REG_SYS_PW_CTRL);
        mmio.write8(REG_SYS_PW_CTRL, v | (1 << 3));
        mmio.write8(REG_SYS_PW_CTRL, v & !(1 << 3));
        for _ in 0..5_000 {
            if (mmio.read8(addr) & mask) == want {
                return true;
            }
            mmio.delay_us(20);
        }
        false
    }

    fn pwr_write_mask<M: Rtw88Mmio>(&self, mmio: &mut M, addr: u32, mask: u8, val: u8) {
        let cur = mmio.read8(addr);
        mmio.write8(addr, (cur & !mask) | (val & mask));
    }

    fn mac_pre_system_cfg<M: Rtw88Mmio>(&self, mmio: &mut M) {
        mmio.write8(REG_RSV_CTRL, 0);
        let hci_opt = mmio.read32(REG_HCI_OPT_CTRL);
        mmio.write32(REG_HCI_OPT_CTRL, hci_opt | (1u32 << 8)); // BIT_USB_SUS_DIS

        let pad1 = mmio.read32(REG_PAD_CTRL1) | (1u32 << 29) | (1u32 << 28);
        mmio.write32(REG_PAD_CTRL1, pad1);

        let led = mmio.read32(REG_LED_CFG) & !((1u32 << 25) | (1u32 << 26));
        mmio.write32(REG_LED_CFG, led);

        let mux = mmio.read32(REG_GPIO_MUXCFG) | (1u32 << 2);
        mmio.write32(REG_GPIO_MUXCFG, mux);

        let fen = mmio.read8(REG_SYS_FUNC_EN) & !0x03;
        mmio.write8(REG_SYS_FUNC_EN, fen);

        let rf = mmio.read8(REG_RF_CTRL) & !0x07;
        mmio.write8(REG_RF_CTRL, rf);

        let wlrf1 = mmio.read32(REG_WLRF1) & !((1u32 << 24) | (1u32 << 25) | (1u32 << 26));
        mmio.write32(REG_WLRF1, wlrf1);
    }

    fn run_pwr_on_seq_8821c<M: Rtw88Mmio>(&self, mmio: &mut M) -> Result<(), RtwError> {
        // trans_carddis_to_cardemu_8821c (PCI-applicable entries)
        self.pwr_write_mask(mmio, 0x0005, (1 << 3) | (1 << 4) | (1 << 7), 0);
        self.pwr_write_mask(mmio, 0x0300, 0xFF, 0);
        self.pwr_write_mask(mmio, 0x0301, 0xFF, 0);

        // trans_cardemu_to_act_8821c (PCI-applicable entries)
        self.pwr_write_mask(mmio, 0x0005, (1 << 4) | (1 << 3) | (1 << 2), 0);
        self.pwr_write_mask(mmio, 0x0075, 1 << 0, 1 << 0);
        if !self.pwr_poll(mmio, 0x0006, 1 << 1, 1 << 1) {
            return Err(RtwError::PwrSeqTimeout);
        }
        self.pwr_write_mask(mmio, 0x0075, 1 << 0, 0);
        self.pwr_write_mask(mmio, 0x0006, 1 << 0, 1 << 0);
        self.pwr_write_mask(mmio, 0x0005, 1 << 7, 0);
        self.pwr_write_mask(mmio, 0x0005, (1 << 4) | (1 << 3), 0);
        self.pwr_write_mask(mmio, 0x0005, 1 << 0, 1 << 0);
        if !self.pwr_poll(mmio, 0x0005, 1 << 0, 0) {
            return Err(RtwError::PwrSeqTimeout);
        }
        self.pwr_write_mask(mmio, 0x0020, 1 << 3, 1 << 3);
        self.pwr_write_mask(mmio, 0x0074, 1 << 5, 1 << 5);
        self.pwr_write_mask(mmio, 0x0022, 1 << 1, 0);
        self.pwr_write_mask(mmio, 0x0062, (1 << 7) | (1 << 6) | (1 << 5), 0xE0);
        self.pwr_write_mask(mmio, 0x0061, (1 << 7) | (1 << 6) | (1 << 5), 0);
        self.pwr_write_mask(mmio, 0x007C, 1 << 1, 0);
        Ok(())
    }

    fn run_pwr_off_seq_8821c<M: Rtw88Mmio>(&self, mmio: &mut M) {
        // trans_act_to_cardemu_8821c (PCI-applicable entries)
        self.pwr_write_mask(mmio, 0x0093, 1 << 3, 0);
        self.pwr_write_mask(mmio, 0x001F, 0xFF, 0);
        self.pwr_write_mask(mmio, 0x0049, 1 << 1, 0);
        self.pwr_write_mask(mmio, 0x0006, 1 << 0, 1 << 0);
        self.pwr_write_mask(mmio, 0x0002, 1 << 1, 0);
        self.pwr_write_mask(mmio, 0x0005, 1 << 1, 1 << 1);
        let _ = self.pwr_poll(mmio, 0x0005, 1 << 1, 0);
        self.pwr_write_mask(mmio, 0x0020, 1 << 3, 0);
        // trans_cardemu_to_carddis_8821c (PCI-applicable entries from rtw8821c.c)
        self.pwr_write_mask(mmio, 0x0067, 1 << 5, 0);
        self.pwr_write_mask(mmio, 0x0005, 1 << 2, 1 << 2);
        self.pwr_write_mask(mmio, 0x0081, (1 << 7) | (1 << 6), 0);
        self.pwr_write_mask(mmio, 0x0090, 1 << 1, 0);
    }

    fn mac_power_on<M: Rtw88Mmio>(&self, mmio: &mut M) -> Result<(), RtwError> {
        self.mac_pre_system_cfg(mmio);
        // If WCPU3081 firmware is still active after warm VFIO handoff (no PCIe FLR),
        // toggle RPWM (`rtw_mac_power_switch`, `mac.c:280`) before cycling power.
        if mmio.read16(REG_MCUFW_CTRL) == 0xC078 {
            let rpwm = (mmio.read8(REG_PCIE_HRPWM1) ^ (1 << 7)) & (1 << 7);
            mmio.write8(REG_PCIE_HRPWM1, rpwm);
        }
        if mmio.read8(REG_CR) != 0xEA {
            // Card was already powered from host OS/BIOS/warm reboot — cleanly cycle it
            self.run_pwr_off_seq_8821c(mmio);
            self.mac_pre_system_cfg(mmio);
        }
        self.run_pwr_on_seq_8821c(mmio)?;

        // `__rtw_mac_init_system_cfg`
        let dmem = mmio.read32(REG_CPU_DMEM_CON) | (1u32 << 16) | (1u32 << 8);
        mmio.write32(REG_CPU_DMEM_CON, dmem);

        let fen_hi = mmio.read8(REG_SYS_FUNC_EN + 1) | 0xD8; // chip->sys_func_en
        mmio.write8(REG_SYS_FUNC_EN + 1, fen_hi);

        let cr_ext3 = (mmio.read8(REG_CR_EXT + 3) & 0xF0) | 0x0C;
        mmio.write8(REG_CR_EXT + 3, cr_ext3);

        let mcufw = mmio.read32(REG_MCUFW_CTRL);
        if (mcufw & (1u32 << 20)) != 0 {
            mmio.write32(REG_MCUFW_CTRL, mcufw & !(1u32 << 20));
            let mux = mmio.read32(REG_GPIO_MUXCFG) & !(1u32 << 19);
            mmio.write32(REG_GPIO_MUXCFG, mux);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Physical + Logical 512B EFUSE Dump (`rtw_parse_efuse_map`)
    // -----------------------------------------------------------------------

    fn read_efuse<M: Rtw88Mmio>(&mut self, mmio: &mut M) {
        const PHY_SZ: usize = 512;
        const PROTECT_SZ: usize = 96;
        const LOG_SZ: usize = 512;
        let mut phy = [0xFFu8; PHY_SZ];
        let mut log = [0xFFu8; LOG_SZ];

        // Grant EFUSE access, select Wi-Fi bank 0, disable LDO25
        mmio.write8(REG_EFUSE_ACCESS, 0x69);
        let ldo = mmio.read32(REG_LDO_EFUSE_CTRL) & !((1u32 << 8) | (1u32 << 9));
        mmio.write32(REG_LDO_EFUSE_CTRL, ldo);
        let ldo3 = mmio.read8(REG_LDO_EFUSE_CTRL + 3) & !(1u8 << 7);
        mmio.write8(REG_LDO_EFUSE_CTRL + 3, ldo3);

        let mut ctl = mmio.read32(REG_EFUSE_CTRL);
        let mut read_ok = true;
        for (addr, slot) in phy.iter_mut().enumerate() {
            ctl &= !(0x0003_FFFF); // clear data [7:0] + addr [17:8]
            ctl |= ((addr as u32) & 0x3FF) << 8;
            mmio.write32(REG_EFUSE_CTRL, ctl & !(1u32 << 31));
            let mut done = false;
            for _ in 0..10_000 {
                ctl = mmio.read32(REG_EFUSE_CTRL);
                if (ctl & (1u32 << 31)) != 0 {
                    done = true;
                    break;
                }
                mmio.delay_us(1);
            }
            if !done {
                read_ok = false;
                break;
            }
            *slot = (ctl & 0xFF) as u8;
        }
        mmio.write8(REG_EFUSE_ACCESS, 0x00);
        if !read_ok {
            return;
        }

        // Decode Realtek 1-byte / 2-byte EFUSE packet stream into logical map
        let limit = PHY_SZ - PROTECT_SZ;
        let mut phy_idx = 0usize;
        while phy_idx + 1 < limit {
            let hdr1 = phy[phy_idx];
            let hdr2 = phy[phy_idx + 1];
            if hdr1 == 0xFF || ((hdr1 & 0x1F) == 0x0F && hdr2 == 0xFF) {
                break;
            }
            let (blk_idx, word_en) = if (hdr1 & 0x1F) == 0x0F {
                let b = (((hdr2 & 0xF0) >> 1) | ((hdr1 >> 5) & 0x07)) as usize;
                phy_idx += 2;
                (b, hdr2 & 0x0F)
            } else {
                let b = ((hdr1 & 0xF0) >> 4) as usize;
                phy_idx += 1;
                (b, hdr1 & 0x0F)
            };
            for word in 0..4usize {
                if (word_en & (1u8 << word)) != 0 {
                    continue;
                }
                let log_idx = (blk_idx << 3) + (word << 1);
                if phy_idx + 2 > limit || log_idx + 2 > LOG_SZ {
                    break;
                }
                log[log_idx] = phy[phy_idx];
                log[log_idx + 1] = phy[phy_idx + 1];
                phy_idx += 2;
            }
        }

        // Parse `struct rtw8821c_efuse` + `struct rtw8821ce_efuse` (`0xD0`)
        let rtl_id = u16::from_le_bytes([log[0], log[1]]);
        let rfe_raw = log[0xCA];
        let rfe_option = if rfe_raw == 0xFF { 0 } else { rfe_raw & 0x1F };
        let pkg_type = if rfe_raw != 0xFF && (rfe_raw & (1 << 5)) != 0 {
            1
        } else {
            0
        };
        let rfe_btg = matches!(rfe_option, 0x2 | 0x4 | 0x7 | 0xA | 0xC | 0xF);
        let xtal_k = if log[0xB9] == 0xFF {
            0x20
        } else {
            log[0xB9] & 0x3F
        };
        let thermal = if log[0xBA] == 0xFF { 0x1A } else { log[0xBA] };
        let swing_2g = if log[0xC6] == 0xFF { 0 } else { log[0xC6] };
        let swing_5g = if log[0xC7] == 0xFF { 0 } else { log[0xC7] };
        let cc = if log[0xCB] != 0xFF && log[0xCC] != 0xFF {
            [log[0xCB], log[0xCC]]
        } else {
            *b"00"
        };

        let mut txpwr_2g_cck = [0x28u8; 6];
        for (i, slot) in txpwr_2g_cck.iter_mut().enumerate() {
            let v = log[0x10 + i];
            if v != 0 && v < 0x3F {
                *slot = v;
            }
        }
        let mut txpwr_2g_bw40 = [0x28u8; 5];
        for (i, slot) in txpwr_2g_bw40.iter_mut().enumerate() {
            let v = log[0x16 + i];
            if v != 0 && v < 0x3F {
                *slot = v;
            }
        }
        let mut txpwr_5g_bw40 = [0x28u8; 14];
        for (i, slot) in txpwr_5g_bw40.iter_mut().enumerate() {
            let v = log[0x22 + i];
            if v != 0 && v < 0x3F {
                *slot = v;
            }
        }

        let mut mac = [0u8; 6];
        mac.copy_from_slice(&log[0xD0..0xD6]);
        if mac == [0; 6] || mac == [0xFF; 6] || (mac[0] & 1) != 0 {
            // Fall back to existing REG_MACID if BIOS preloaded it
            mac = crate::read_hw_mac(mmio);
        }

        self.efuse = Rtw8821cEfuseInfo {
            mac_addr: mac,
            rfe_option,
            rfe_btg,
            pkg_type,
            crystal_cap: xtal_k,
            thermal_meter: thermal,
            tx_bb_swing_2g: swing_2g,
            tx_bb_swing_5g: swing_5g,
            txpwr_2g_cck,
            txpwr_2g_bw40,
            txpwr_5g_bw40,
            country_code: cc,
            efuse_valid: rtl_id == 0x8129 || rtl_id == 0x8821 || log[0xD0] != 0xFF,
        };
    }

    pub fn program_mac_addr<M: Rtw88Mmio>(&self, mmio: &mut M, mac: &[u8; 6]) {
        for (i, &b) in mac.iter().enumerate() {
            mmio.write8(REG_MACID + i as u32, b);
        }
    }

    // -----------------------------------------------------------------------
    // TRXFF / Auto-LLT / H2C Ring Setup (`rtw_init_trx_cfg`)
    // -----------------------------------------------------------------------

    fn init_trx_cfg<M: Rtw88Mmio>(&self, mmio: &mut M) -> Result<(), RtwError> {
        // `rqpn_table_8821c[1]`: vo=NORMAL(2), vi=NORMAL(2), be=LOW(1), bk=LOW(1), mg=EXTRA(3), hi=HIGH(0)
        // Wait: Realtek enum rtw_dma_mapping: HIGH=1, NORMAL=2, LOW=3, EXTRA=4? Let's match exact bits:
        // HIGH=1, NORMAL=2, LOW=3, EXTRA=4? Wait: in Realtek main.h:
        // RTW_DMA_MAPPING_EXTRA=0, LOW=1, NORMAL=2, HIGH=3!
        // Let's verify: in `download_firmware_reg_backup`, `RTW_DMA_MAPPING_HIGH << 6` in `REG_TXDMA_PQ_MAP + 1` (bits [15:14] of u16)!
        let pq_map: u16 = (2u16 << 4)  // VO -> NORMAL(2)
            | (2u16 << 6)  // VI -> NORMAL(2)
            | (1u16 << 8)  // BE -> LOW(1)
            | (1u16 << 10) // BK -> LOW(1), MG -> EXTRA(0)
            | (3u16 << 14); // HI -> HIGH(3)
        mmio.write16(REG_TXDMA_PQ_MAP, pq_map);
        mmio.write8(REG_CR, 0);
        mmio.write8(REG_CR, 0xFF); // MAC_TRX_ENABLE
        mmio.write32(REG_H2CQ_CSR, 1u32 << 31); // BIT_H2CQ_FULL

        // `page_table_8821c[1]`: hq=16, lq=16, nq=16, exq=14, gapq=1
        let pubq = self.fifo.acq_pg_num - 16 - 16 - 16 - 14 - 1;
        mmio.write16(REG_FIFOPAGE_INFO_1, 16);
        mmio.write16(REG_FIFOPAGE_INFO_2, 16);
        mmio.write16(REG_FIFOPAGE_INFO_3, 16);
        mmio.write16(REG_FIFOPAGE_INFO_4, 14);
        mmio.write16(REG_FIFOPAGE_INFO_5, pubq);
        let rqpn2 = mmio.read32(REG_RQPN_CTRL_2) | (1u32 << 31);
        mmio.write32(REG_RQPN_CTRL_2, rqpn2);

        mmio.write16(REG_FIFOPAGE_CTRL_2, self.fifo.rsvd_boundary);
        let fwhw2 = mmio.read8(REG_FWHW_TXQ_CTRL + 2) | (1u8 << 4); // BIT_EN_WR_FREE_TAIL >> 16
        mmio.write8(REG_FWHW_TXQ_CTRL + 2, fwhw2);

        mmio.write16(REG_BCNQ_BDNY_V1, self.fifo.rsvd_boundary);
        mmio.write16(REG_FIFOPAGE_CTRL_2 + 2, self.fifo.rsvd_boundary);
        mmio.write16(REG_BCNQ1_BDNY_V1, self.fifo.rsvd_boundary);
        mmio.write32(REG_RXFF_BNDY, RTL8821C_RXFF_SIZE - C2H_PKT_BUF - 1);

        let llt = mmio.read8(REG_AUTO_LLT_V1) | 1;
        mmio.write8(REG_AUTO_LLT_V1, llt);
        let mut llt_ok = false;
        for _ in 0..20_000 {
            if (mmio.read8(REG_AUTO_LLT_V1) & 1) == 0 {
                llt_ok = true;
                break;
            }
            mmio.delay_us(25);
        }
        if !llt_ok {
            return Err(RtwError::AutoLltTimeout);
        }
        mmio.write8(REG_CR + 3, 0);

        // `init_h2c`
        let h2cq_addr = u32::from(self.fifo.rsvd_h2cq_addr) << TX_PAGE_SIZE_SHIFT;
        let h2cq_size = 8u32 << TX_PAGE_SIZE_SHIFT;
        let head = (mmio.read32(REG_H2C_HEAD) & 0xFFFC_0000) | h2cq_addr;
        mmio.write32(REG_H2C_HEAD, head);
        let rd = (mmio.read32(REG_H2C_READ_ADDR) & 0xFFFC_0000) | h2cq_addr;
        mmio.write32(REG_H2C_READ_ADDR, rd);
        let tail = (mmio.read32(REG_H2C_TAIL) & 0xFFFC_0000) | (h2cq_addr + h2cq_size);
        mmio.write32(REG_H2C_TAIL, tail);

        let mut info = (mmio.read8(REG_H2C_INFO) & 0xFC) | 0x01;
        mmio.write8(REG_H2C_INFO, info);
        info = (mmio.read8(REG_H2C_INFO) & 0xFB) | 0x04;
        mmio.write8(REG_H2C_INFO, info);
        let chk = (mmio.read8(REG_TXDMA_OFFSET_CHK + 1) & 0x7F) | 0x80;
        mmio.write8(REG_TXDMA_OFFSET_CHK + 1, chk);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Firmware Download via BCNQ `rsvd_page` + IDDMA (`__rtw_download_firmware`)
    // -----------------------------------------------------------------------

    fn ltecoex_wait_ready<M: Rtw88Mmio>(&self, mmio: &mut M) -> Result<(), RtwError> {
        for _ in 0..5_000 {
            if (mmio.read32(REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1) & LTECOEX_READY) != 0 {
                return Ok(());
            }
            mmio.delay_us(20);
        }
        Err(RtwError::LteCoexTimeout)
    }

    fn ltecoex_read_reg<M: Rtw88Mmio>(&self, mmio: &mut M, offset: u16) -> Result<u32, RtwError> {
        self.ltecoex_wait_ready(mmio)?;
        mmio.write32(
            REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1,
            0x800F_0000 | u32::from(offset),
        );
        Ok(mmio.read32(REG_WL2LTECOEX_INDIRECT_ACCESS_READ_DATA_V1))
    }

    fn ltecoex_write_reg<M: Rtw88Mmio>(
        &self,
        mmio: &mut M,
        offset: u16,
        value: u32,
    ) -> Result<(), RtwError> {
        self.ltecoex_wait_ready(mmio)?;
        mmio.write32(REG_WL2LTECOEX_INDIRECT_ACCESS_WRITE_DATA_V1, value);
        mmio.write32(
            REG_WL2LTECOEX_INDIRECT_ACCESS_CTRL_V1,
            0xC00F_0000 | u32::from(offset),
        );
        Ok(())
    }

    fn ltecoex_write_mask<M: Rtw88Mmio>(&self, mmio: &mut M, offset: u16, mask: u32, val: u32) {
        if mask == 0 {
            return;
        }
        if let Ok(cur) = self.ltecoex_read_reg(mmio, offset) {
            let shift = mask.trailing_zeros();
            let next = (cur & !mask) | ((val << shift) & mask);
            let _ = self.ltecoex_write_reg(mmio, offset, next);
        }
    }

    fn wlan_cpu_enable<M: Rtw88Mmio>(&self, mmio: &mut M, enable: bool) {
        if enable {
            let rsv = mmio.read8(REG_RSV_CTRL + 1) | 0x01;
            mmio.write8(REG_RSV_CTRL + 1, rsv);
            let fen = mmio.read8(REG_SYS_FUNC_EN + 1) | (1 << 2);
            mmio.write8(REG_SYS_FUNC_EN + 1, fen);
        } else {
            let fen = mmio.read8(REG_SYS_FUNC_EN + 1) & !(1 << 2);
            mmio.write8(REG_SYS_FUNC_EN + 1, fen);
            let rsv = mmio.read8(REG_RSV_CTRL + 1) & !0x01;
            mmio.write8(REG_RSV_CTRL + 1, rsv);
        }
    }

    /// Write a payload into TX FIFO reserved page `pg_addr` via `BCNQ` DMA
    /// (`rtw_fw_write_data_rsvd_page` + `rtw_pci_write_data_rsvd_page`).
    pub fn write_rsvd_page<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
        pg_addr: u16,
        payload: &[u8],
        tim_offset: u8,
    ) -> Result<(), RtwError> {
        if payload.is_empty() {
            return Err(RtwError::MalformedDescriptor);
        }
        let bcn_ring = self.tx_rings[RtwTxQueue::Bcn as usize];
        if RTW_TX_DESC_SIZE + payload.len() > bcn_ring.buf_stride {
            return Err(RtwError::MalformedDescriptor);
        }

        // Save `REG_CR + 1`, `REG_FWHW_TXQ_CTRL + 2`, and `REG_BCN_CTRL` (`fw.c:1485..1507`)
        let bckp_bcn = mmio.read8(REG_BCN_CTRL);
        let bckp_cr1 = mmio.read8(REG_CR + 1);
        let bckp_fwhw2 = mmio.read8(REG_FWHW_TXQ_CTRL + 2);

        // Clear BIT_BCN_VALID_V1 (RW1C bit 15) in REG_FIFOPAGE_CTRL_2 and set target page
        mmio.write16(REG_FIFOPAGE_CTRL_2, (pg_addr & 0x0FFF) | (1u16 << 15));

        // Enable SW Beacon (`BIT_ENSWBCN >> 8` = bit 0 of `REG_CR + 1`)
        mmio.write8(REG_CR + 1, bckp_cr1 | 0x01);

        // Disable hardware TBTT beacon function while uploading reserved page
        mmio.write8(REG_BCN_CTRL, (bckp_bcn & !(1 << 3)) | (1 << 4));

        // On PCIe, `BIT_EN_BCNQ_DL` (`BIT(22)` => bit 6 of `REG_FWHW_TXQ_CTRL + 2`) MUST be CLEARED
        mmio.write8(REG_FWHW_TXQ_CTRL + 2, bckp_fwhw2 & !(1 << 6));

        // Build 48-byte PCIe TX descriptor with QSEL_BEACON (16) (`w7 = 0` on PCIe)
        let mut desc = [0u8; RTW_TX_DESC_SIZE];
        build_full_tx_desc(
            payload.len() as u16,
            16, // TX_DESC_QSEL_BEACON
            DESC_RATE1M,
            true,
            false,
            0,
            0,
            tim_offset,
            &mut desc,
        );

        let pkt_off = bcn_ring.buf_off;
        dma.write_bytes(pkt_off, &desc);
        dma.write_bytes(pkt_off + RTW_TX_DESC_SIZE, payload);

        let pkt_pa = dma.phys_base().wrapping_add(pkt_off as u32);
        let total_len = RTW_TX_DESC_SIZE + payload.len();
        let psb_len = (((total_len - 1) / 128 + 1) as u16) | (1u16 << 15); // OWN bit

        let mut bd = [0u8; RTW_PCI_TX_BD_SIZE];
        bd[0..2].copy_from_slice(&(RTW_TX_DESC_SIZE as u16).to_le_bytes());
        bd[2..4].copy_from_slice(&psb_len.to_le_bytes());
        bd[4..8].copy_from_slice(&pkt_pa.to_le_bytes());
        bd[8..10].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        bd[12..16].copy_from_slice(&(pkt_pa.wrapping_add(RTW_TX_DESC_SIZE as u32)).to_le_bytes());
        dma.write_bytes(bcn_ring.bd_off, &bd);

        // Kick BCNQ transfer (`RTK_PCI_TXBD_BCN_WORK |= BIT_PCI_BCNQ_FLAG`)
        let work = mmio.read8(RTK_PCI_TXBD_BCN_WORK) | (1 << 4);
        mmio.write8(RTK_PCI_TXBD_BCN_WORK, work);

        // Poll BIT_BCN_VALID_V1 (bit 15 of REG_FIFOPAGE_CTRL_2) up to ~500 ms
        let mut bcn_ok = false;
        for _ in 0..20_000 {
            if (mmio.read16(REG_FIFOPAGE_CTRL_2) & (1u16 << 15)) != 0 {
                bcn_ok = true;
                break;
            }
            mmio.delay_us(25);
        }

        // Restore reserved-page head & backed-up registers (`fw.c:1529..1535`)
        mmio.write16(
            REG_FIFOPAGE_CTRL_2,
            (self.fifo.rsvd_boundary & 0x0FFF) | (1u16 << 15),
        );
        mmio.write8(REG_BCN_CTRL, bckp_bcn);
        mmio.write8(REG_FWHW_TXQ_CTRL + 2, bckp_fwhw2);
        mmio.write8(REG_CR + 1, bckp_cr1);

        if bcn_ok {
            Ok(())
        } else {
            Err(RtwError::RsvdPageBcnValidTimeout)
        }
    }

    fn iddma_copy_chunk<M: Rtw88Mmio>(
        &self,
        mmio: &mut M,
        src: u32,
        dst: u32,
        len: u32,
        first_chunk: bool,
    ) -> Result<(), RtwError> {
        let mut idle = false;
        for _ in 0..5_000 {
            if (mmio.read32(REG_DDMA_CH0CTRL) & (1u32 << 31)) == 0 {
                idle = true;
                break;
            }
            mmio.delay_us(10);
        }
        if !idle {
            return Err(RtwError::IddmaTimeout);
        }
        let mut ctrl = (1u32 << 31) | (1u32 << 29) | (len & 0x3FFFF);
        if !first_chunk {
            ctrl |= 1u32 << 24; // BIT_DDMACH0_CHKSUM_CONT
        }
        mmio.write32(REG_DDMA_CH0SA, src);
        mmio.write32(REG_DDMA_CH0DA, dst);
        mmio.write32(REG_DDMA_CH0CTRL, ctrl);
        for _ in 0..20_000 {
            if (mmio.read32(REG_DDMA_CH0CTRL) & (1u32 << 31)) == 0 {
                return Ok(());
            }
            mmio.delay_us(25);
        }
        Err(RtwError::IddmaTimeout)
    }

    fn download_fw_section<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
        section: &[u8],
        dst_addr: u32,
    ) -> Result<(), RtwError> {
        let mut ch0 = mmio.read32(REG_DDMA_CH0CTRL);
        ch0 |= 1u32 << 25; // BIT_DDMACH0_RESET_CHKSUM_STS
        mmio.write32(REG_DDMA_CH0CTRL, ch0);

        let mut offset = 0usize;
        let mut first = true;
        while offset < section.len() {
            let pkt_sz = (section.len() - offset).min(0x1000);
            self.write_rsvd_page(mmio, dma, 0, &section[offset..offset + pkt_sz], 0)?;
            self.iddma_copy_chunk(
                mmio,
                OCPBASE_TXBUF_88XX + RTW_TX_DESC_SIZE as u32,
                dst_addr.wrapping_add(offset as u32),
                pkt_sz as u32,
                first,
            )?;
            first = false;
            offset += pkt_sz;
        }

        // Verify hardware DDMA checksum (`check_fw_checksum`)
        let mut fw_ctrl = mmio.read8(REG_MCUFW_CTRL);
        let bad_csum = (mmio.read32(REG_DDMA_CH0CTRL) & (1u32 << 27)) != 0;
        if bad_csum {
            if dst_addr < OCPBASE_DMEM_88XX {
                fw_ctrl = (fw_ctrl | (1 << 3)) & !(1 << 4);
            } else {
                fw_ctrl = (fw_ctrl | (1 << 5)) & !(1 << 6);
            }
            mmio.write8(REG_MCUFW_CTRL, fw_ctrl);
            return Err(RtwError::FirmwareChecksumMismatch);
        }
        if dst_addr < OCPBASE_DMEM_88XX {
            fw_ctrl |= (1 << 3) | (1 << 4); // BIT_IMEM_DW_OK | BIT_IMEM_CHKSUM_OK
        } else {
            fw_ctrl |= (1 << 5) | (1 << 6); // BIT_DMEM_DW_OK | BIT_DMEM_CHKSUM_OK
        }
        mmio.write8(REG_MCUFW_CTRL, fw_ctrl);
        Ok(())
    }

    fn download_firmware<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
        fw_blob: &[u8],
        info: &Rtw88FirmwareInfo,
    ) -> Result<(), RtwError> {
        let mem_usage = fw_blob[0x18];
        let dmem_addr =
            u32::from_le_bytes([fw_blob[0x20], fw_blob[0x21], fw_blob[0x22], fw_blob[0x23]])
                & !(1u32 << 31);
        let emem_addr =
            u32::from_le_bytes([fw_blob[0x38], fw_blob[0x39], fw_blob[0x3A], fw_blob[0x3B]])
                & !(1u32 << 31);
        let imem_addr =
            u32::from_le_bytes([fw_blob[0x3C], fw_blob[0x3D], fw_blob[0x3E], fw_blob[0x3F]])
                & !(1u32 << 31);

        let dmem_len = (info.dmem_size + FW_HDR_CHKSUM_SIZE) as usize;
        let imem_len = (info.imem_size + FW_HDR_CHKSUM_SIZE) as usize;
        let emem_len = if (mem_usage & (1 << 4)) != 0 && info.emem_size > 0 {
            (info.emem_size + FW_HDR_CHKSUM_SIZE) as usize
        } else {
            0
        };
        if RTW88_FW_HDR_LEN + dmem_len + imem_len + emem_len > fw_blob.len() {
            return Err(RtwError::FirmwareSectionOutOfBounds);
        }

        // Backup LTECoex indirect register 0x38 before disabling WCPU (`mac.c:788`)
        let ltecoex_bckp = self.ltecoex_read_reg(mmio, LTE_COEX_CTRL)?;

        self.wlan_cpu_enable(mmio, false);

        // Backup registers modified during DLFW
        let b_pq = mmio.read8(REG_TXDMA_PQ_MAP + 1);
        let b_cr = mmio.read8(REG_CR);
        let b_fp1 = mmio.read16(REG_FIFOPAGE_INFO_1);
        let b_rqpn2 = mmio.read32(REG_RQPN_CTRL_2) | (1u32 << 31);
        let b_bcn = mmio.read8(REG_BCN_CTRL);

        mmio.write8(REG_TXDMA_PQ_MAP + 1, 3u8 << 6); // HIQ -> HIGH(3)
        mmio.write8(REG_CR, 0x05); // BIT_HCI_TXDMA_EN | BIT_TXDMA_EN
        mmio.write32(REG_H2CQ_CSR, 1u32 << 31);
        mmio.write16(REG_FIFOPAGE_INFO_1, 0x200);
        mmio.write32(REG_RQPN_CTRL_2, b_rqpn2);
        mmio.write8(REG_BCN_CTRL, (b_bcn & !(1 << 3)) | (1 << 4));

        // Reset WCPU platform & clock
        let dmem2 = mmio.read8(REG_CPU_DMEM_CON + 2);
        mmio.write8(REG_CPU_DMEM_CON + 2, dmem2 & !0x01);
        let clk1 = mmio.read8(REG_SYS_CLK_CTRL + 1);
        mmio.write8(REG_SYS_CLK_CTRL + 1, clk1 & !(1 << 6));
        mmio.write8(REG_CPU_DMEM_CON + 2, dmem2 | 0x01);
        mmio.write8(REG_SYS_CLK_CTRL + 1, clk1 | (1 << 6));

        let mcufw = (mmio.read16(REG_MCUFW_CTRL) & 0x3800) | 0x0001; // BIT_MCUFWDL_EN
        mmio.write16(REG_MCUFW_CTRL, mcufw);

        let dmem_slice = &fw_blob[RTW88_FW_HDR_LEN..RTW88_FW_HDR_LEN + dmem_len];
        let imem_off = RTW88_FW_HDR_LEN + dmem_len;
        let imem_slice = &fw_blob[imem_off..imem_off + imem_len];

        let dl_res = self
            .download_fw_section(mmio, dma, dmem_slice, dmem_addr)
            .and_then(|()| self.download_fw_section(mmio, dma, imem_slice, imem_addr))
            .and_then(|()| {
                if emem_len > 0 {
                    let emem_off = imem_off + imem_len;
                    self.download_fw_section(
                        mmio,
                        dma,
                        &fw_blob[emem_off..emem_off + emem_len],
                        emem_addr,
                    )
                } else {
                    Ok(())
                }
            });

        // Restore backed-up registers regardless
        mmio.write8(REG_TXDMA_PQ_MAP + 1, b_pq);
        mmio.write8(REG_CR, b_cr);
        mmio.write32(REG_H2CQ_CSR, 1u32 << 31);
        mmio.write16(REG_FIFOPAGE_INFO_1, b_fp1);
        mmio.write32(REG_RQPN_CTRL_2, b_rqpn2);
        mmio.write8(REG_BCN_CTRL, b_bcn);

        if let Err(e) = dl_res {
            let c = mmio.read8(REG_MCUFW_CTRL) & !0x01;
            mmio.write8(REG_MCUFW_CTRL, c);
            let fen = mmio.read8(REG_SYS_FUNC_EN + 1) | (1 << 2);
            mmio.write8(REG_SYS_FUNC_EN + 1, fen);
            return Err(e);
        }

        // `download_firmware_end_flow` (`mac.c:761..774`)
        mmio.write32(REG_TXDMA_STATUS, 1u32 << 2); // BTI_PAGE_OVF
        let mut ctrl16 = mmio.read16(REG_MCUFW_CTRL);
        if (ctrl16 & 0x0050) != 0x0050 {
            let c = mmio.read8(REG_MCUFW_CTRL) & !0x01;
            mmio.write8(REG_MCUFW_CTRL, c);
            return Err(RtwError::FirmwareChecksumMismatch);
        }
        ctrl16 = (ctrl16 | (1u16 << 14)) & !0x0001; // BIT_FW_DW_RDY & ~BIT_MCUFWDL_EN
        mmio.write16(REG_MCUFW_CTRL, ctrl16);

        self.wlan_cpu_enable(mmio, true);

        // Restore LTECoex indirect register 0x38 after enabling WCPU (`mac.c:807`)
        if let Err(e) = self.ltecoex_write_reg(mmio, LTE_COEX_CTRL, ltecoex_bckp) {
            let c = mmio.read8(REG_MCUFW_CTRL) & !0x01;
            mmio.write8(REG_MCUFW_CTRL, c);
            let fen = mmio.read8(REG_SYS_FUNC_EN + 1) | (1 << 2);
            mmio.write8(REG_SYS_FUNC_EN + 1, fen);
            return Err(e);
        }

        // Poll `FW_READY` (`0xC078` under mask `0xFFFF & ~BIT_CPU_CLK_SEL` = `0xCFFF`)
        const FW_READY_MASK: u16 = 0xCFFF;
        const FW_READY_VAL: u16 = (1 << 15) | (1 << 14) | (1 << 6) | (1 << 5) | (1 << 4) | (1 << 3);
        for _ in 0..20_000 {
            if (mmio.read16(REG_MCUFW_CTRL) & FW_READY_MASK) == FW_READY_VAL {
                self.h2c_mbox = 0;
                self.h2c_seq = 0;
                return Ok(());
            }
            mmio.delay_us(25);
        }
        let c = mmio.read8(REG_MCUFW_CTRL) & !0x01;
        mmio.write8(REG_MCUFW_CTRL, c);
        let fen = mmio.read8(REG_SYS_FUNC_EN + 1) | (1 << 2);
        mmio.write8(REG_SYS_FUNC_EN + 1, fen);
        Err(RtwError::WcpuBootTimeout)
    }

    // -----------------------------------------------------------------------
    // 8821C MAC, PHY, AGC & RF Table Initialization
    // -----------------------------------------------------------------------

    fn mac_init_8821c<M: Rtw88Mmio>(&self, mmio: &mut M) {
        mmio.write8(REG_AMPDU_MAX_TIME_V1, 0x70);
        let hang = mmio.read8(REG_TX_HANG_CTRL) | (1 << 2);
        mmio.write8(REG_TX_HANG_CTRL, hang);
        let pre_txcnt: u16 = 0x01E4 | (1 << 11);
        mmio.write8(REG_PRECNT_CTRL, (pre_txcnt & 0xFF) as u8);
        mmio.write8(REG_PRECNT_CTRL + 1, (pre_txcnt >> 8) as u8);
        mmio.write32(REG_PROT_MODE_CTRL, 0x2020_08FF);
        mmio.write16(REG_BAR_MODE_CTRL + 2, 0x0801);
        mmio.write8(REG_FAST_EDCA_VOVI_SETTING, 0x06);
        mmio.write8(REG_FAST_EDCA_VOVI_SETTING + 2, 0x06);
        mmio.write8(REG_FAST_EDCA_BEBK_SETTING, 0x06);
        mmio.write8(REG_FAST_EDCA_BEBK_SETTING + 2, 0x06);
        let inirts = mmio.read8(REG_INIRTS_RATE_SEL) | (1 << 5);
        mmio.write8(REG_INIRTS_RATE_SEL, inirts);

        let t0 = mmio.read8(REG_TIMER0_SRC_SEL) & !0x70;
        mmio.write8(REG_TIMER0_SRC_SEL, t0);
        mmio.write16(REG_TXPAUSE, 0);
        mmio.write8(REG_SLOT, 0x09);
        mmio.write8(REG_PIFS, 0x19);
        mmio.write32(REG_SIFS, 0x1010_0E0A);
        mmio.write16(REG_EDCA_VO_PARAM + 2, 0x0186);
        mmio.write16(REG_EDCA_VI_PARAM + 2, 0x03BC);
        mmio.write32(REG_RD_NAV_NXT, 0x001B_0005);
        mmio.write16(REG_RXTSF_OFFSET_CCK, 0x3030);

        let bcn = mmio.read8(REG_BCN_CTRL) | (1 << 3);
        mmio.write8(REG_BCN_CTRL, bcn);
        mmio.write32(REG_TBTT_PROHIBIT, 0x0000_6404);
        mmio.write8(REG_DRVERLYINT, 0x04);
        mmio.write8(REG_BCNDMATIM, 0x02);
        let ptcl = mmio.read8(REG_TX_PTCL_CTRL + 1) & !(1 << 4);
        mmio.write8(REG_TX_PTCL_CTRL + 1, ptcl);

        mmio.write16(REG_RXFLTMAP0, 0xFFFF);
        mmio.write16(REG_RXFLTMAP1, 0x0FFF);
        mmio.write16(REG_RXFLTMAP2, 0xFFFF);
        mmio.write32(REG_RCR, 0xE400_220E);
        mmio.write8(REG_RX_PKT_LIMIT, 24); // 12288 >> 9
        mmio.write8(REG_TCR + 2, 0x30);
        mmio.write8(REG_TCR + 1, 0x30);
        mmio.write8(REG_ACKTO_CCK, 0x40);
        let trx_h = mmio.read8(REG_WMAC_TRXPTCL_CTL_H) | (1 << 1);
        mmio.write8(REG_WMAC_TRXPTCL_CTL_H, trx_h);
        let snd = mmio.read8(REG_SND_PTCL_CTRL) | (1 << 4);
        mmio.write8(REG_SND_PTCL_CTRL, snd);
        mmio.write32(REG_WMAC_OPTION_FUNCTION + 8, 0xB081_0041);
        mmio.write8(REG_WMAC_OPTION_FUNCTION + 4, 0x98);
    }

    fn drv_info_cfg<M: Rtw88Mmio>(&self, mmio: &mut M) {
        mmio.write8(REG_RX_DRVINFO_SZ, PHY_STATUS_SIZE);
        let bndy1 = (mmio.read8(REG_TRXFF_BNDY + 1) & 0xF0) | 0x0F;
        mmio.write8(REG_TRXFF_BNDY + 1, bndy1);
        let rcr = mmio.read32(REG_RCR) | (1u32 << 28);
        mmio.write32(REG_RCR, rcr);
        let opt = mmio.read32(REG_WMAC_OPTION_FUNCTION + 4) & !((1u32 << 8) | (1u32 << 9));
        mmio.write32(REG_WMAC_OPTION_FUNCTION + 4, opt);
    }

    pub fn read_rf<M: Rtw88Mmio>(&self, mmio: &M, addr: u32, mask: u32) -> u32 {
        let direct = RF_BASE_ADDR_A + ((addr & 0xFF) << 2);
        let m = mask & RFREG_MASK;
        if m == 0 {
            return 0;
        }
        let raw = mmio.read32(direct) & RFREG_MASK;
        (raw & m) >> m.trailing_zeros()
    }

    pub fn write_rf<M: Rtw88Mmio>(&self, mmio: &mut M, addr: u32, mask: u32, data: u32) {
        let m = mask & RFREG_MASK;
        if m == 0 {
            return;
        }
        let val = if m != RFREG_MASK {
            let old = self.read_rf(mmio, addr, RFREG_MASK);
            let shift = m.trailing_zeros();
            (old & !m) | ((data << shift) & m)
        } else {
            data & RFREG_MASK
        };
        let packed = (((addr & 0xFF) << 20) | (val & 0x000F_FFFF)) & 0x0FFF_FFFF;
        mmio.write32(REG_LSSI_WRITE_A, packed);
        mmio.delay_us(13);
    }

    fn write32_mask<M: Rtw88Mmio>(&self, mmio: &mut M, addr: u32, mask: u32, val: u32) {
        if mask == 0xFFFF_FFFF {
            mmio.write32(addr, val);
            return;
        }
        let shift = mask.trailing_zeros();
        let old = mmio.read32(addr);
        mmio.write32(addr, (old & !mask) | ((val << shift) & mask));
    }

    fn check_phy_cond(&self, cond: u32) -> bool {
        let c_rfe = (cond & 0xFF) as u8;
        let c_intf = ((cond >> 8) & 0x0F) as u8;
        let c_pkg = ((cond >> 12) & 0x0F) as u8;
        let c_cut = ((cond >> 24) & 0x0F) as u8;

        let drv_cut = if self.cut_version == 0 {
            15u8
        } else {
            (1u8 << (self.cut_version + 1)) & 0x0F
        };
        let drv_pkg = if self.efuse.pkg_type == 0 {
            15u8
        } else {
            1u8 << self.efuse.pkg_type
        };
        let drv_intf = 0x01u8; // INTF_PCIE

        if c_cut != 0 && (c_cut & drv_cut) == 0 && c_cut != self.cut_version {
            return false;
        }
        if c_pkg != 0 && (c_pkg & drv_pkg) == 0 && c_pkg != self.efuse.pkg_type {
            return false;
        }
        if c_intf != 0 && (c_intf & drv_intf) == 0 {
            return false;
        }
        if c_rfe != self.efuse.rfe_option {
            return false;
        }
        true
    }

    fn load_cond_table<M: Rtw88Mmio>(&self, mmio: &mut M, pairs: &[u32], kind: u8) {
        let mut is_matched = true;
        let mut is_skipped = false;
        let mut pos_cond = 0u32;

        let mut i = 0usize;
        while i + 1 < pairs.len() {
            let w0 = pairs[i];
            let w1 = pairs[i + 1];
            i += 2;

            let pos = (w0 >> 31) != 0;
            let neg = ((w0 >> 30) & 1) != 0;
            if pos {
                let branch = (w0 >> 28) & 0x03;
                match branch {
                    3 => {
                        // BRANCH_ENDIF
                        is_matched = true;
                        is_skipped = false;
                    }
                    2 => {
                        // BRANCH_ELSE
                        is_matched = !is_skipped;
                    }
                    _ => {
                        pos_cond = w0;
                    }
                }
            } else if neg {
                if !is_skipped {
                    if self.check_phy_cond(pos_cond) {
                        is_matched = true;
                        is_skipped = true;
                    } else {
                        is_matched = false;
                        is_skipped = false;
                    }
                } else {
                    is_matched = false;
                }
            } else if is_matched {
                match kind {
                    0 => mmio.write8(w0, w1 as u8), // MAC
                    1 => mmio.write32(w0, w1),      // AGC
                    2 => match w0 {
                        // BB
                        0xFE => mmio.delay_us(50_000),
                        0xFD => mmio.delay_us(5_000),
                        0xFC => mmio.delay_us(1_000),
                        0xFB => mmio.delay_us(50),
                        0xFA => mmio.delay_us(5),
                        0xF9 => mmio.delay_us(1),
                        _ => mmio.write32(w0, w1),
                    },
                    _ => match w0 {
                        // RF Path A
                        0xFFE => mmio.delay_us(50_000),
                        0xFE => mmio.delay_us(100),
                        _ => {
                            self.write_rf(mmio, w0, RFREG_MASK, w1);
                            mmio.delay_us(1);
                        }
                    },
                }
            }
        }
    }

    fn phy_set_param_8821c<M: Rtw88Mmio>(&mut self, mmio: &mut M) {
        let mut fen = mmio.read8(REG_SYS_FUNC_EN) | (1 << 6); // BIT_FEN_PCIEA
        mmio.write8(REG_SYS_FUNC_EN, fen);

        // Toggle BB reset
        fen |= 0x03;
        mmio.write8(REG_SYS_FUNC_EN, fen);
        fen &= !0x03;
        mmio.write8(REG_SYS_FUNC_EN, fen);
        fen |= 0x03;
        mmio.write8(REG_SYS_FUNC_EN, fen);

        mmio.write8(REG_RF_CTRL, 0x07);
        mmio.delay_us(10);
        mmio.write8(REG_WLRF1 + 3, 0x07);
        mmio.delay_us(10);

        const BIT_RX_PSEL_RST: u32 = (1u32 << 28) | (1u32 << 29);
        let rxpsel = mmio.read32(REG_RXPSEL) & !BIT_RX_PSEL_RST;
        mmio.write32(REG_RXPSEL, rxpsel);

        // Load all authentic 8821C silicon tables
        self.load_cond_table(mmio, RTW8821C_MAC_TBL, 0);
        self.load_cond_table(mmio, RTW8821C_BB_TBL, 2);
        self.load_cond_table(mmio, RTW8821C_AGC_TBL, 1);
        if matches!(self.efuse.rfe_option, 2 | 4) {
            self.load_cond_table(mmio, RTW8821C_AGC_BTG_TYPE2_TBL, 1);
        }
        self.load_cond_table(mmio, RTW8821C_RF_A_TBL, 3);

        let xtal = u32::from(self.efuse.crystal_cap & 0x3F);
        self.write32_mask(mmio, REG_AFE_XTAL_CTRL, 0x7E00_0000, xtal);
        self.write32_mask(mmio, REG_AFE_PLL_CTRL, 0x0000_007E, xtal);
        self.write32_mask(mmio, REG_CCK0_FAREPORT, (1u32 << 18) | (1u32 << 22), 0);

        let rxpsel_post = mmio.read32(REG_RXPSEL) | BIT_RX_PSEL_RST;
        mmio.write32(REG_RXPSEL, rxpsel_post);

        self.ch_param[0] = mmio.read32(REG_TXSF2);
        self.ch_param[1] = mmio.read32(REG_TXSF6);
        self.ch_param[2] = mmio.read32(REG_TXFILTER);
        self.cck_pd_default = mmio.read8(REG_CSRATIO) & 0x1F;

        // Set DIG Initial Gain (`REG_RXIGI_A[6:0]`) to `chip->dig_min = 0x1C`
        // (`rtw_phy_dig_init` / `rtw_phy_dig_set_max_coverage`) for full RX sensitivity.
        self.write32_mask(mmio, REG_RXIGI_A, 0x0000_007F, 0x1C);

        // Beamforming grouping bitmap (`rtw8821c_phy_bf_init`)
        mmio.write32(0x1C94, 0xAFFF_AFFF);
    }

    /// Initialize 8821C Wi-Fi + Bluetooth hardware PTA coexistence (`rtw8821c_coex_cfg_init` +
    /// `__rtw_coex_init_hw_config` + Scoreboard `REG_WIFI_BT_INFO`) so Wi-Fi works cleanly
    /// even when the combo card's USB Bluetooth side is simultaneously active on a host OS.
    fn coex_init_hw_config_8821c<M: Rtw88Mmio>(&self, mmio: &mut M) {
        // 1. Enable TBTT function & BT statistics / sample rate (`rtw8821c_coex_cfg_init`)
        let bcn = mmio.read8(REG_BCN_CTRL) | (1 << 3);
        mmio.write8(REG_BCN_CTRL, bcn);
        let tdma_time = (mmio.read8(REG_BT_TDMA_TIME) & !0x3F) | 0x05;
        mmio.write8(REG_BT_TDMA_TIME, tdma_time);
        mmio.write8(REG_BT_STAT_CTRL, 0x01); // BT_CNT_ENABLE

        // 2. Enable 3-wire PTA between WL and BT (`BIT_BT_PTA_EN | BIT_PO_BT_PTA_PINS`)
        //    and clear debug overrides (`rtw8821c_coex_cfg_gnt_debug`)
        let mut gpio_mux = mmio.read32(REG_GPIO_MUXCFG);
        gpio_mux = (gpio_mux | (1u32 << 5) | (1u32 << 9)) & !(1u32 << 19);
        mmio.write32(REG_GPIO_MUXCFG, gpio_mux);

        let mut qctrl = mmio.read8(REG_QUEUE_CTRL);
        qctrl = (qctrl | (1 << 4)) & !(1 << 5); // BIT_PTA_WL_TX_EN=1, BIT_PTA_EDCCA_EN=0
        mmio.write8(REG_QUEUE_CTRL, qctrl);

        let bt_coex_v2 = mmio.read16(REG_BT_COEX_V2) | (1u16 << 12); // BIT_GNT_BT_POLARITY
        mmio.write16(REG_BT_COEX_V2, bt_coex_v2);

        // High-priority WL masks (`TX_RSP`, `TX_BEACON`, `RX_SCAN`, `TX_BEACONQ`)
        let tbl_h0 = mmio.read8(REG_BT_COEX_TABLE_H) | (1 << 3) | (1 << 4);
        mmio.write8(REG_BT_COEX_TABLE_H, tbl_h0);
        let tbl_h3 = mmio.read8(REG_BT_COEX_TABLE_H + 3) | (1 << 3); // BIT_BCN_QUEUE
        mmio.write8(REG_BT_COEX_TABLE_H + 3, tbl_h3);

        // Shared-antenna PTA slot arbitration (`table_sant_8821c[4]` = 0x5A5A_5A5A:
        // grants WL RX/TX against low-pri BT while preserving BT A2DP/SCO high-pri)
        mmio.write32(REG_BT_COEX_TABLE0, 0x5A5A_5A5A);
        mmio.write32(REG_BT_COEX_TABLE1, 0x5A5A_5A5A);
        mmio.write32(REG_BT_COEX_BRK_TABLE, 0xF0FF_FFFF);

        // Clear GNT debug / SDIO pins (`rtw8821c_coex_cfg_gnt_debug`)
        let sdio = mmio.read32(REG_SYS_SDIO_CTRL) & !((1u32 << 18) | (1u32 << 27));
        mmio.write32(REG_SYS_SDIO_CTRL, sdio);

        // Notify Bluetooth MCU via Scoreboard (`COEX_SCBD_ACTIVE | COEX_SCBD_ONOFF | BIT_BT_INT_EN`)
        mmio.write16(REG_WIFI_BT_INFO, (1u16 << 15) | 0x0003);

        // Configure initial 2.4 GHz PTA & external DPDT/SPDT antenna switch
        self.coex_set_ant_path_8821c(mmio, false);
    }

    /// Program external M.2 DPDT/SPDT antenna switch & `LTE_COEX_CTRL` GNT lines
    /// for 2.4 GHz (`COEX_SET_ANT_2G`) or 5 GHz (`COEX_SET_ANT_5G`), strictly
    /// following `rtw8821c_coex_cfg_rfe_type` + `rtw8821c_coex_cfg_ant_switch`.
    fn coex_set_ant_path_8821c<M: Rtw88Mmio>(&self, mmio: &mut M, is_5g: bool) {
        // 1. Decode board RFE topology (`rtw8821c_coex_cfg_rfe_type`, `rtw8821c.c:947..987`)
        let rfe_type = self.efuse.rfe_option;
        let wlg_at_btg = matches!(rfe_type, 2 | 4 | 7 | 10 | 12 | 15);
        let polarity_inverse = matches!(rfe_type, 3 | 4 | 11 | 12);

        // 2. Give LTE/PTA mux ownership to WL (`BIT_LTE_MUX_CTRL_PATH = BIT(26)` of `0x0070`)
        let mux = mmio.read8(REG_SYS_SDIO_CTRL + 3) | (1 << 2);
        mmio.write8(REG_SYS_SDIO_CTRL + 3, mux);

        // 3. Program `LTE_COEX_CTRL` (0x0038):
        //    - 2.4 GHz (`COEX_SET_ANT_2G`): `GNT_BT = HW_PTA (0x0)`, `GNT_WL = HW_PTA (0x0)`
        //    - 5 GHz   (`COEX_SET_ANT_5G`): `GNT_BT = HW_PTA (0x0)`, `GNT_WL = SW_HIGH (0x3)`
        let gnt_wl = if is_5g { 0x3 } else { 0x0 };
        self.ltecoex_write_mask(mmio, LTE_COEX_CTRL, 0xC000, 0x0);
        self.ltecoex_write_mask(mmio, LTE_COEX_CTRL, 0x0C00, 0x0);
        self.ltecoex_write_mask(mmio, LTE_COEX_CTRL, 0x3000, gnt_wl);
        self.ltecoex_write_mask(mmio, LTE_COEX_CTRL, 0x0300, gnt_wl);

        // 4. Hand DPDT control from BT to WL/BB (`REG_LED_CFG`: clear `BIT_DPDT_SEL_EN = BIT(23)`,
        //    set `BIT_DPDT_WL_SEL = BIT(24)`)
        let mut led = mmio.read32(REG_LED_CFG);
        led = (led & !(1u32 << 23)) | (1u32 << 24);
        mmio.write32(REG_LED_CFG, led);

        // 5. Clear `BIT_BT_BTG_SEL` (`BIT(31)` of `REG_PAD_CTRL1` = bit 7 of `0x0067`) and
        //    enable `BIT_CTRL_TYPE1 | BIT_CTRL_TYPE2` (`BIT(5) | BIT(4)` of `REG_CTRL_TYPE = 0x0067`)
        let mut ctrl = mmio.read8(REG_CTRL_TYPE);
        ctrl = (ctrl & !(1 << 7)) | (1 << 5) | (1 << 4);
        mmio.write8(REG_CTRL_TYPE, ctrl);

        // 6. Select RFE_CTRL8 pin mux (`[7:0]`) and DPDT switch nibble (`[31:28]`, `0xF000_0000`)
        //    (`rtw8821c_coex_cfg_ant_switch`, `rtw8821c.c:850..901`)
        let (pin_mux, regval): (u32, u32) = if wlg_at_btg {
            // `COEX_SWITCH_CTRL_BY_BBSW` (`DPDT_CTRL_PIN = 0x77`)
            let rv = if polarity_inverse {
                // `pos_type = COEX_SWITCH_TO_WLA`, `polarity_inverse = true` => `0x2`
                0x2
            } else if rfe_type != 4 && rfe_type != 2 {
                // `pos_type = COEX_SWITCH_TO_WLG_BT` => `0x3`
                0x3
            } else {
                0x2
            };
            (0x77, rv)
        } else if is_5g {
            // `COEX_SET_ANT_5G`: `COEX_SWITCH_CTRL_BY_BBSW`, `COEX_SWITCH_TO_WLA`
            let rv = if !polarity_inverse { 0x1 } else { 0x2 };
            (0x77, rv)
        } else {
            // `COEX_SET_ANT_2G`: `COEX_SWITCH_CTRL_BY_PTA` (`PTA_CTRL_PIN = 0x66`)
            let rv = if !polarity_inverse { 0x2 } else { 0x1 };
            (0x66, rv)
        };
        self.write32_mask(mmio, REG_RFE_CTRL8, 0x0000_00FF, pin_mux);
        self.write32_mask(mmio, REG_RFE_CTRL8, 0xF000_0000, regval);
    }

    /// Program per-rate Path-A TX power indices (`0x1D00..0x1D54`) from factory EFUSE
    /// (`rtw8821c_set_tx_power_index`, `rtw8821c.c:685..722`). Without this, `0x1D00..`
    /// remains `0x00` (~ -16 dBm), making transmitted Probe Requests / Auth frames inaudible.
    fn set_tx_power_index_8821c<M: Rtw88Mmio>(&self, mmio: &mut M, ch: u8) {
        let pack4 = |p: u8| -> u32 {
            let b = u32::from(p.min(0x3F));
            b | (b << 8) | (b << 16) | (b << 24)
        };
        if ch <= 14 {
            let grp_cck = match ch {
                1..=2 => 0,
                3..=5 => 1,
                6..=8 => 2,
                9..=11 => 3,
                12..=13 => 4,
                _ => 5,
            };
            let grp_ofdm = grp_cck.min(4);
            let cck_w = pack4(self.efuse.txpwr_2g_cck[grp_cck]);
            let ofdm_w = pack4(self.efuse.txpwr_2g_bw40[grp_ofdm]);
            // CCK 1M/2M/5.5M/11M (`0x00..0x03`)
            mmio.write32(REG_TXAGC_A_BASE, cck_w);
            // OFDM 6M..54M (`0x04..0x0B`), HT MCS0..7 (`0x0C..0x13`), VHT 1SS MCS0..9 (`0x2C..0x35`)
            for off in [0x04u32, 0x08, 0x0C, 0x10, 0x2C, 0x30] {
                mmio.write32(REG_TXAGC_A_BASE + off, ofdm_w);
            }
            let p = u32::from(self.efuse.txpwr_2g_bw40[grp_ofdm].min(0x3F));
            mmio.write32(REG_TXAGC_A_BASE + 0x34, p | (p << 8));
        } else {
            let grp_5g = match ch {
                36..=42 => 0,
                44..=48 => 1,
                50..=58 => 2,
                60..=64 => 3,
                100..=106 => 4,
                108..=114 => 5,
                116..=122 => 6,
                124..=130 => 7,
                132..=138 => 8,
                140..=144 => 9,
                149..=155 => 10,
                157..=161 => 11,
                _ => 12,
            };
            let w = pack4(self.efuse.txpwr_5g_bw40[grp_5g]);
            for off in [0x04u32, 0x08, 0x0C, 0x10, 0x2C, 0x30] {
                mmio.write32(REG_TXAGC_A_BASE + off, w);
            }
            let p = u32::from(self.efuse.txpwr_5g_bw40[grp_5g].min(0x3F));
            mmio.write32(REG_TXAGC_A_BASE + 0x34, p | (p << 8));
        }
    }

    fn enable_sec_engine<M: Rtw88Mmio>(&self, mmio: &mut M) {
        let cr = mmio.read16(REG_CR) | (1u16 << 9); // RTW_SEC_ENGINE_EN
        mmio.write16(REG_CR, cr);
        let sec = mmio.read16(RTW_SEC_CONFIG)
            | (1 << 0) // TX_UNI_USE_DK
            | (1 << 1) // RX_UNI_USE_DK
            | (1 << 2) // TX_DEC_EN
            | (1 << 3) // RX_DEC_EN
            | (1 << 6) // TX_BC_USE_DK
            | (1 << 7); // RX_BC_USE_DK
        mmio.write16(RTW_SEC_CONFIG, sec);
    }

    // -----------------------------------------------------------------------
    // 2.4 GHz & 5 GHz Channel Synthesizer (`rtw8821c_set_channel`)
    // -----------------------------------------------------------------------

    pub fn set_channel<M: Rtw88Mmio>(&mut self, mmio: &mut M, channel: u8, bw_mhz: u8) {
        let ch = if channel == 0 { 1 } else { channel };
        self.current_channel = ch;
        self.current_bw_mhz = bw_mhz;

        // 1. BB channel config
        if ch <= 14 {
            self.write32_mask(mmio, REG_RXPSEL, 1 << 28, 1);
            self.write32_mask(mmio, REG_CCK_CHECK, 1 << 7, 0);
            self.write32_mask(mmio, REG_ENTXCCK, 1 << 18, 0);
            self.write32_mask(mmio, REG_RXCCAMSK, 0x0000_FC00, 15);
            self.write32_mask(mmio, REG_TXSCALE_A, 0x0F00, 0x0);
            self.write32_mask(mmio, REG_CLKTRK, 0x1FFE_0000, 0x96A);
            if ch == 14 {
                mmio.write32(REG_TXSF2, 0x0000_B81C);
                self.write32_mask(mmio, REG_TXSF6, 0x0000_FFFF, 0x0000);
                mmio.write32(REG_TXFILTER, 0x0000_3667);
            } else {
                mmio.write32(REG_TXSF2, self.ch_param[0]);
                self.write32_mask(mmio, REG_TXSF6, 0x0000_FFFF, self.ch_param[1] & 0xFFFF);
                mmio.write32(REG_TXFILTER, self.ch_param[2]);
            }
        } else {
            self.write32_mask(mmio, REG_ENTXCCK, 1 << 18, 1);
            self.write32_mask(mmio, REG_CCK_CHECK, 1 << 7, 1);
            self.write32_mask(mmio, REG_RXPSEL, 1 << 28, 0);
            self.write32_mask(mmio, REG_RXCCAMSK, 0x0000_FC00, 15);
            let scale = if ch <= 64 {
                1
            } else if ch <= 144 {
                2
            } else {
                3
            };
            self.write32_mask(mmio, REG_TXSCALE_A, 0x0F00, scale);
            let clktrk = if ch <= 48 {
                0x494
            } else if ch <= 64 {
                0x453
            } else if ch <= 116 {
                0x452
            } else {
                0x412
            };
            self.write32_mask(mmio, REG_CLKTRK, 0x1FFE_0000, clktrk);
        }

        // BW ADC clock
        let mut adc = mmio.read32(REG_ADCCLK);
        match bw_mhz {
            40 => {
                adc = (adc & 0xFF3F_F300) | 0x2002_0001;
                mmio.write32(REG_ADCCLK, adc);
            }
            80 => {
                adc = (adc & 0xFCFF_CF00) | 0x4004_0002;
                mmio.write32(REG_ADCCLK, adc);
            }
            _ => {
                adc = (adc & 0xFFCF_FC00) | 0x1001_0000;
                mmio.write32(REG_ADCCLK, adc);
            }
        }
        self.write32_mask(mmio, REG_ADC160, 1 << 30, 1);

        // 2. BB TX swing
        const SWING_MAP: [u32; 4] = [0x200, 0x16A, 0x101, 0x0B6];
        let raw_swing = if ch <= 14 {
            self.efuse.tx_bb_swing_2g
        } else {
            self.efuse.tx_bb_swing_5g
        };
        let swing_idx = if raw_swing > 9 {
            0
        } else {
            (raw_swing / 3) as usize
        };
        self.write32_mask(mmio, REG_TXSCALE_A, 0xFFE0_0000, SWING_MAP[swing_idx]);

        // 3. MAC channel config (`rtw_set_channel_mac`)
        mmio.write8(REG_DATA_SC, 0);
        let mut trxptcl = mmio.read32(REG_WMAC_TRXPTCL_CTL) & !((1 << 7) | (1 << 8));
        if bw_mhz == 80 {
            trxptcl |= 1 << 8;
        } else if bw_mhz == 40 {
            trxptcl |= 1 << 7;
        }
        mmio.write32(REG_WMAC_TRXPTCL_CTL, trxptcl);

        let afe1 = mmio.read32(REG_AFE_CTRL1) & !((1 << 20) | (1 << 21));
        mmio.write32(REG_AFE_CTRL1, afe1);
        mmio.write8(REG_USTIME_TSF, 80);
        mmio.write8(REG_USTIME_EDCA, 80);
        let mut cck_chk = mmio.read8(REG_CCK_CHECK) & !(1 << 7);
        if ch > 14 {
            cck_chk |= 1 << 7;
        }
        mmio.write8(REG_CCK_CHECK, cck_chk);

        // 4. RF front-end switch + RF 0x18 synthesizer (`rtw8821c_set_channel_rf`)
        let dmem = mmio.read32(REG_DMEM_CTRL) | (1 << 16);
        mmio.write32(REG_DMEM_CTRL, dmem);
        let sys = mmio.read32(REG_SYS_CTRL) | (1 << 26);
        mmio.write32(REG_SYS_CTRL, sys);

        let mut rfectl = mmio.read32(REG_RFECTL);
        // Authentic `rtw8821c.h:251..255` internal RFE switch bitmasks & 2.4G LNA/CCA:
        //   B_BTG_SWITCH  = BIT(16)
        //   B_CTRL_SWITCH = BIT(18)
        //   B_WL_SWITCH   = BIT(20) | BIT(22)
        //   B_WLG_SWITCH  = BIT(21)
        //   B_WLA_SWITCH  = BIT(23)
        //   BTG_LNA = 0xFC84 (BTG_CCA = 0x0E), WLG_LNA = 0x7532 (WLG_CCA = 0x12)
        const B_BTG_SWITCH: u32 = 1 << 16;
        const B_CTRL_SWITCH: u32 = 1 << 18;
        const B_WL_SWITCH: u32 = (1 << 20) | (1 << 22);
        const B_WLG_SWITCH: u32 = 1 << 21;
        const B_WLA_SWITCH: u32 = 1 << 23;
        const BTG_LNA: u32 = 0xFC84;
        const WLG_LNA: u32 = 0x7532;
        if ch <= 14 {
            if self.efuse.rfe_btg {
                rfectl = (rfectl | B_BTG_SWITCH)
                    & !(B_CTRL_SWITCH | B_WL_SWITCH | B_WLG_SWITCH | B_WLA_SWITCH);
                self.write32_mask(mmio, REG_ENRXCCA, 0x00FF_0000, 0x0E);
                self.write32_mask(mmio, REG_ENTXCCK, 0x0000_FFFF, BTG_LNA);
            } else {
                rfectl = (rfectl | B_WL_SWITCH | B_WLG_SWITCH)
                    & !(B_BTG_SWITCH | B_CTRL_SWITCH | B_WLA_SWITCH);
                self.write32_mask(mmio, REG_ENRXCCA, 0x00FF_0000, 0x12);
                self.write32_mask(mmio, REG_ENTXCCK, 0x0000_FFFF, WLG_LNA);
            }
            mmio.write32(REG_RFECTL, rfectl);
            self.write_rf(mmio, RF_LUTDBG, 1 << 6, 1);
            self.write_rf(mmio, 0x64, 0x0F, 0x0F);
        } else {
            rfectl = (rfectl | B_WL_SWITCH | B_WLA_SWITCH)
                & !(B_BTG_SWITCH | B_CTRL_SWITCH | B_WLG_SWITCH);
            mmio.write32(REG_RFECTL, rfectl);
            self.write_rf(mmio, RF_LUTDBG, 1 << 6, 0);
        }

        // RF 0x18 bitmasks (`rtw8821c.h`):
        // RF18_BAND_MASK = BIT(16) | BIT(9) | BIT(8) (2G = 0, 5G = BIT(16) | BIT(8))
        // RF18_CHANNEL_MASK = 0xFF
        // RF18_RFSI_MASK = BIT(18) | BIT(17) (GE 100..140 => BIT(17), GT 140 => BIT(18))
        // RF18_BW_MASK = BIT(11) | BIT(10) (20M = BIT(11)|BIT(10), 40M = BIT(11), 80M = BIT(10))
        const RF18_BAND_MASK: u32 = (1 << 16) | (1 << 9) | (1 << 8);
        const RF18_RFSI_MASK: u32 = (1 << 18) | (1 << 17);
        const RF18_BW_MASK: u32 = (1 << 11) | (1 << 10);

        let mut rf18 = self.read_rf(mmio, RF_CFGCH, RFREG_MASK);
        rf18 &= !(RF18_BAND_MASK | 0xFF | RF18_RFSI_MASK | RF18_BW_MASK);
        if ch > 14 {
            rf18 |= (1 << 16) | (1 << 8);
        }
        rf18 |= u32::from(ch);
        if (100..=140).contains(&ch) {
            rf18 |= 1 << 17;
        } else if ch > 140 {
            rf18 |= 1 << 18;
        }
        rf18 |= match bw_mhz {
            80 => 1 << 10,
            40 => 1 << 11,
            _ => (1 << 11) | (1 << 10),
        };
        self.write_rf(mmio, RF_CFGCH, RFREG_MASK, rf18);
        self.write_rf(mmio, RF_XTALX2, 1 << 19, 0);
        self.write_rf(mmio, RF_XTALX2, 1 << 19, 1);

        // 5. RX DFIR (`rtw8821c_set_channel_rxdfir`)
        self.write32_mask(mmio, REG_ACBB0, (1 << 29) | (1 << 28), 0x2);
        if bw_mhz == 80 {
            self.write32_mask(mmio, REG_ACBBRXFIR, (1 << 29) | (1 << 28), 0x1);
            self.write32_mask(mmio, REG_TXDFIR, 1 << 31, 0);
            self.write32_mask(mmio, REG_CHFIR, 1 << 31, 1);
        } else if bw_mhz == 40 {
            self.write32_mask(mmio, REG_ACBBRXFIR, (1 << 29) | (1 << 28), 0x2);
            self.write32_mask(mmio, REG_TXDFIR, 1 << 31, 0);
            self.write32_mask(mmio, REG_CHFIR, 1 << 31, 0);
        } else {
            self.write32_mask(mmio, REG_ACBBRXFIR, (1 << 29) | (1 << 28), 0x2);
            self.write32_mask(mmio, REG_TXDFIR, 1 << 31, 1);
            self.write32_mask(mmio, REG_CHFIR, 1 << 31, 0);
        }

        // 6. Program external DPDT/PTA antenna path (`COEX_SET_ANT_2G` / `COEX_SET_ANT_5G`),
        //    per-rate TX power (`rtw_phy_set_tx_power_level`), and DIG RX gain (`0x1C`).
        self.coex_set_ant_path_8821c(mmio, ch > 14);
        self.set_tx_power_index_8821c(mmio, ch);
        self.write32_mask(mmio, REG_RXIGI_A, 0x0000_007F, 0x1C);
    }

    // -----------------------------------------------------------------------
    // H2C Mailbox & Packet Queue (`H2CQ`) + Firmware IQK
    // -----------------------------------------------------------------------

    pub fn send_h2c_cmd<M: Rtw88Mmio>(
        &mut self,
        mmio: &mut M,
        cmd: &[u8; 8],
    ) -> Result<(), RtwError> {
        let box_id = self.h2c_mbox & 0x03;
        let (box_reg, box_ex_reg) = match box_id {
            0 => (REG_HMEBOX0, REG_HMEBOX0_EX),
            1 => (REG_HMEBOX1, REG_HMEBOX1_EX),
            2 => (REG_HMEBOX2, REG_HMEBOX2_EX),
            _ => (REG_HMEBOX3, REG_HMEBOX3_EX),
        };
        let mut ready = false;
        for _ in 0..500 {
            if ((mmio.read8(REG_HMETFR) >> box_id) & 1) == 0 {
                ready = true;
                break;
            }
            mmio.delay_us(20);
        }
        if !ready {
            return Err(RtwError::HardwareTimeout);
        }
        let w0 = u32::from_le_bytes([cmd[0], cmd[1], cmd[2], cmd[3]]);
        let w1 = u32::from_le_bytes([cmd[4], cmd[5], cmd[6], cmd[7]]);
        mmio.write32(box_ex_reg, w1);
        mmio.write32(box_reg, w0);
        self.h2c_mbox = (box_id + 1) & 0x03;
        Ok(())
    }

    pub fn send_h2c_pkt<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
        sub_cmd_id: u16,
        payload: &[u8],
    ) -> Result<(), RtwError> {
        let mut pkt = [0u8; 32];
        let body_len = payload.len().min(24);
        let total_len = (8 + body_len) as u16;
        let dw0 = 0x01u32 | (0xFFu32 << 8) | (u32::from(sub_cmd_id) << 16);
        let dw1 = u32::from(total_len) | (u32::from(self.h2c_seq) << 16);
        self.h2c_seq = self.h2c_seq.wrapping_add(1);
        pkt[0..4].copy_from_slice(&dw0.to_le_bytes());
        pkt[4..8].copy_from_slice(&dw1.to_le_bytes());
        pkt[8..8 + body_len].copy_from_slice(&payload[..body_len]);
        self.tx_raw_ring(mmio, dma, RtwTxQueue::H2c, &pkt, DESC_RATE6M, false, false)
    }

    fn send_fw_general_info<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
    ) -> Result<(), RtwError> {
        let mut body = [0u8; 4];
        body[2] = self
            .fifo
            .rsvd_fw_txbuf_addr
            .saturating_sub(self.fifo.rsvd_boundary) as u8;
        self.send_h2c_pkt(mmio, dma, 0x0D, &body)
    }

    fn send_fw_phydm_info<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
    ) -> Result<(), RtwError> {
        // ref_type=rfe_option, rf_type=FW_RF_1T1R(4), cut_ver, rx_ant=1, tx_ant=1
        let body = [self.efuse.rfe_option, 4, self.cut_version, 0x11];
        self.send_h2c_pkt(mmio, dma, 0x11, &body)
    }

    pub fn trigger_iqk<M: Rtw88Mmio, D: Rtw88Dma>(&mut self, mmio: &mut M, dma: &mut D) {
        let _ = self.send_h2c_pkt(mmio, dma, 0x0E, &[0x00, 0x00, 0x00, 0x00]);
        for _ in 0..200 {
            if self.read_rf(mmio, RF_DTXLOK, RFREG_MASK) == 0xABCDE {
                self.write_rf(mmio, RF_DTXLOK, RFREG_MASK, 0);
                break;
            }
            mmio.delay_us(200);
        }
    }

    pub fn report_media_status<M: Rtw88Mmio>(&mut self, mmio: &mut M, mac_id: u8, connected: bool) {
        let mut cmd = [0u8; 8];
        cmd[0] = 0x01; // H2C_CMD_MEDIA_STATUS_RPT
        cmd[1] = u8::from(connected);
        cmd[2] = mac_id;
        let _ = self.send_h2c_cmd(mmio, &cmd);

        if connected {
            // Also configure Rate Adaptation (`H2C_CMD_RA_INFO` = 0x40) for 1SS B/G/N/AC
            let mut ra = [0u8; 8];
            ra[0] = 0x40;
            ra[1] = mac_id;
            ra[2] = 3 | (1 << 7); // RTW_RATEID_BGN_20M_1SS | DIS_PT
            ra[3] = 0; // 20MHz
            ra[4..8].copy_from_slice(&0x000F_FFFFu32.to_le_bytes()); // CCK + OFDM + MCS0..7
            let _ = self.send_h2c_cmd(mmio, &ra);
        }
    }

    // -----------------------------------------------------------------------
    // Station & SoftAP Mode + Security CAM
    // -----------------------------------------------------------------------

    pub fn configure_sta_mode<M: Rtw88Mmio>(
        &mut self,
        mmio: &mut M,
        bssid: &[u8; 6],
        linked: bool,
    ) {
        let net_type: u32 = if linked { 2 } else { 0 }; // RTW_NET_MGD_LINKED vs NO_LINK
        self.write32_mask(mmio, REG_CR, 0x0003_0000, net_type);
        let lo = u32::from_le_bytes([bssid[0], bssid[1], bssid[2], bssid[3]]);
        let hi = u16::from_le_bytes([bssid[4], bssid[5]]);
        mmio.write32(REG_BSSID, lo);
        mmio.write16(REG_BSSID + 4, hi);
        mmio.write8(REG_BCN_CTRL, 1 << 3); // BIT_EN_BCN_FUNCTION
        self.report_media_status(mmio, 0, linked);
    }

    /// Switch hardware into real 802.11 AP mode (`RTW_NET_AP_MODE`) and upload
    /// the periodic Beacon MPDU into TX FIFO reserved page 0 so hardware TBTT
    /// transmits beacons autonomously every `beacon_int_tu` TUs (typically 100 ms).
    pub fn configure_ap_mode<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
        ap_bssid: &[u8; 6],
        beacon_mpdu: &[u8],
        beacon_int_tu: u16,
    ) -> Result<(), RtwError> {
        self.program_mac_addr(mmio, ap_bssid);
        let lo = u32::from_le_bytes([ap_bssid[0], ap_bssid[1], ap_bssid[2], ap_bssid[3]]);
        let hi = u16::from_le_bytes([ap_bssid[4], ap_bssid[5]]);
        mmio.write32(REG_BSSID, lo);
        mmio.write16(REG_BSSID + 4, hi);

        // Set `RTW_NET_AP_MODE` (3) in REG_CR [17:16]
        self.write32_mask(mmio, REG_CR, 0x0003_0000, 3);

        // Accept ProbeReq, Auth, AssocReq and all data directed to our BSSID
        // (keep `BIT_TA_BCN = BIT(11)` cleared!)
        let rcr = mmio.read32(REG_RCR) & !((1u32 << 11) | (1u32 << 7) | (1u32 << 6));
        mmio.write32(REG_RCR, rcr);

        mmio.write16(REG_BCNTCFG, 0x0200);
        mmio.write16(0x0518, beacon_int_tu); // REG_BCN_INTERVAL
        self.write_rsvd_page(mmio, dma, self.fifo.rsvd_boundary, beacon_mpdu, 0)?;

        // Enable Beacon function + disable TSF update from external beacons
        mmio.write8(REG_BCN_CTRL, (1 << 3) | (1 << 4));
        Ok(())
    }

    pub fn write_sec_cam<M: Rtw88Mmio>(
        &self,
        mmio: &mut M,
        slot: u8,
        key_idx: u8,
        peer_mac: &[u8; 6],
        is_group: bool,
        aes_ccmp_key: &[u8; 16],
    ) {
        let addr_base = u32::from(slot & 0x1F) << 3;
        let write_cmd = (1u32 << 31) | (1u32 << 16); // POLLING | WRITE_ENABLE
        let mac = if is_group { &[0xFF; 6] } else { peer_mac };
        for i in (0..8u32).rev() {
            let content = match i {
                0 => {
                    u32::from(key_idx & 0x03)
                        | (0x04u32 << 2) // HW_KEY_TYPE_AES (4)
                        | (u32::from(is_group) << 6)
                        | (1u32 << 15) // VALID
                        | (u32::from(mac[0]) << 16)
                        | (u32::from(mac[1]) << 24)
                }
                1 => u32::from_le_bytes([mac[2], mac[3], mac[4], mac[5]]),
                2..=5 => {
                    let j = ((i - 2) * 4) as usize;
                    u32::from_le_bytes([
                        aes_ccmp_key[j],
                        aes_ccmp_key[j + 1],
                        aes_ccmp_key[j + 2],
                        aes_ccmp_key[j + 3],
                    ])
                }
                _ => 0,
            };
            mmio.write32(RTW_SEC_WRITE_REG, content);
            mmio.write32(RTW_SEC_CMD_REG, write_cmd | (addr_base + i));
        }
    }

    pub fn clear_sec_cam<M: Rtw88Mmio>(&self, mmio: &mut M, slot: u8) {
        let addr_base = u32::from(slot & 0x1F) << 3;
        mmio.write32(RTW_SEC_WRITE_REG, 0);
        mmio.write32(RTW_SEC_CMD_REG, (1u32 << 31) | (1u32 << 16) | addr_base);
    }

    // -----------------------------------------------------------------------
    // 8-Queue PCIe TX & MPDU RX Ring Operations
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn tx_raw_ring<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
        queue: RtwTxQueue,
        payload: &[u8],
        rate: u8,
        use_rate: bool,
        hw_aes: bool,
    ) -> Result<(), RtwError> {
        let q = queue as usize;
        if queue == RtwTxQueue::Bcn || payload.is_empty() {
            return Err(RtwError::MalformedDescriptor);
        }
        let idx_reg = TX_QUEUE_IDX_REG[q];
        let hw_rp = mmio.read16(idx_reg + 2) & 0x0FFF;
        self.tx_rings[q].rp = hw_rp;

        let ring = self.tx_rings[q];
        if RTW_TX_DESC_SIZE + payload.len() > ring.buf_stride {
            return Err(RtwError::MalformedDescriptor);
        }
        let next_wp = ((ring.wp as usize + 1) % ring.cap) as u16;
        if next_wp == ring.rp {
            return Err(RtwError::RingFull);
        }

        let is_bmc = payload.len() >= 10 && (payload[4] & 0x01) != 0;
        let seq = self.tx_seq;
        self.tx_seq = (self.tx_seq + 1) & 0x0FFF;

        let mut desc = [0u8; RTW_TX_DESC_SIZE];
        if queue == RtwTxQueue::H2c {
            // `rtw_tx_write_data_h2c_get` (`tx.c:532..555`):
            // `tx_pkt_size = size, qsel = TX_DESC_QSEL_H2C (19), offset = 0, ls = 0, w7 = 0`
            let dw0 = (payload.len() as u32) & 0xFFFF;
            let dw1 = 19u32 << 8; // TX_DESC_QSEL_H2C
            desc[0..4].copy_from_slice(&dw0.to_le_bytes());
            desc[4..8].copy_from_slice(&dw1.to_le_bytes());
        } else {
            build_full_tx_desc(
                payload.len() as u16,
                TX_QUEUE_QSEL[q],
                rate,
                use_rate,
                is_bmc,
                if hw_aes { 0x03 } else { 0x00 }, // SEC_TYPE 3 = AES
                seq,
                0,
                &mut desc,
            );
        }

        let slot = ring.wp as usize;
        let pkt_off = ring.buf_off + slot * ring.buf_stride;
        dma.write_bytes(pkt_off, &desc);
        dma.write_bytes(pkt_off + RTW_TX_DESC_SIZE, payload);

        let pkt_pa = dma.phys_base().wrapping_add(pkt_off as u32);
        let total_len = RTW_TX_DESC_SIZE + payload.len();
        let psb_len = ((total_len - 1) / 128 + 1) as u16;

        let mut bd = [0u8; RTW_PCI_TX_BD_SIZE];
        bd[0..2].copy_from_slice(&(RTW_TX_DESC_SIZE as u16).to_le_bytes());
        bd[2..4].copy_from_slice(&psb_len.to_le_bytes());
        bd[4..8].copy_from_slice(&pkt_pa.to_le_bytes());
        bd[8..10].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        bd[12..16].copy_from_slice(&(pkt_pa.wrapping_add(RTW_TX_DESC_SIZE as u32)).to_le_bytes());
        dma.write_bytes(ring.bd_off + slot * RTW_PCI_TX_BD_SIZE, &bd);

        self.tx_rings[q].wp = next_wp;
        mmio.write16(idx_reg, next_wp & 0x0FFF);
        Ok(())
    }

    /// Transmit an 802.11 Management or Data MPDU on the appropriate hardware queue.
    pub fn transmit_mpdu<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
        mpdu: &[u8],
        is_mgmt: bool,
    ) -> Result<(), RtwError> {
        let queue = if is_mgmt {
            RtwTxQueue::Mgmt
        } else {
            RtwTxQueue::Be
        };
        let is_bmc = mpdu.len() >= 10 && (mpdu[4] & 0x01) != 0;
        let use_basic_rate = is_mgmt || is_bmc;
        let rate = if use_basic_rate {
            if self.current_channel > 14 {
                DESC_RATE6M
            } else {
                DESC_RATE1M
            }
        } else {
            DESC_RATEMCS7
        };
        self.tx_raw_ring(mmio, dma, queue, mpdu, rate, use_basic_rate, false)
    }

    /// Poll and acknowledge pending interrupt status, then pop at most one
    /// received 802.11 MPDU into `out_mpdu` (returning `(mpdu_len, rssi_dbm)`),
    /// while decoding any MCU C2H notifications into `c2h_out`.
    pub fn poll_rx_mpdu<M: Rtw88Mmio, D: Rtw88Dma>(
        &mut self,
        mmio: &mut M,
        dma: &mut D,
        out_mpdu: &mut [u8],
        mut c2h_out: Option<&mut Option<RtwC2hEvent>>,
    ) -> Option<(usize, i8)> {
        // Acknowledge HISR status bits (Write-1-Clear)
        let hisr0 = mmio.read32(RTK_PCI_HISR0);
        if hisr0 != 0 && hisr0 != 0xFFFF_FFFF {
            mmio.write32(RTK_PCI_HISR0, hisr0);
        }
        let hisr3 = mmio.read32(RTK_PCI_HISR3);
        if hisr3 != 0 && hisr3 != 0xFFFF_FFFF {
            mmio.write32(RTK_PCI_HISR3, hisr3);
        }

        let idx_reg = mmio.read32(RTK_PCI_RXBD_IDX_MPDUQ);
        if idx_reg == 0xFFFF_FFFF {
            return None;
        }
        let hw_wp = ((idx_reg >> 16) & 0x0FFF) as u16;

        for _ in 0..8 {
            if self.rx_ring.rp == hw_wp {
                return None;
            }
            let slot = self.rx_ring.rp as usize;
            let buf_off = self.rx_ring.buf_off + slot * RTW_DMA_RX_STRIDE;

            let mut rxd = [0u8; 24];
            dma.read_bytes(buf_off, &mut rxd);

            let w0 = u32::from_le_bytes([rxd[0], rxd[1], rxd[2], rxd[3]]);
            let w2 = u32::from_le_bytes([rxd[8], rxd[9], rxd[10], rxd[11]]);
            let w3 = u32::from_le_bytes([rxd[12], rxd[13], rxd[14], rxd[15]]);

            let pkt_len = (w0 & 0x3FFF) as usize;
            let crc_err = (w0 & (1 << 14)) != 0;
            let icv_err = (w0 & (1 << 15)) != 0;
            let drv_info_sz = (((w0 >> 16) & 0x0F) as usize) * 8;
            let shift = ((w0 >> 24) & 0x03) as usize;
            let has_physt = (w0 & (1 << 26)) != 0;
            let is_c2h = (w2 & (1 << 28)) != 0;
            let rx_rate = (w3 & 0x7F) as u8;

            let pkt_off = 24 + drv_info_sz + shift;
            let mut rssi_dbm: i8 = -60;
            if has_physt && drv_info_sz >= 16 && !is_c2h {
                let mut phy = [0u8; 16];
                dma.read_bytes(buf_off + 24, &mut phy);
                rssi_dbm = decode_8821c_phy_rssi(&phy, rx_rate, self.efuse.rfe_option);
            }

            // Advance ring & recycle RX descriptor
            self.rx_ring.rx_tag = (self.rx_ring.rx_tag + 1) & 0x1FFF;
            let next_rp = ((slot + 1) % self.rx_ring.cap) as u16;
            let buf_pa = dma.phys_base().wrapping_add(buf_off as u32);
            let mut rbd = [0u8; RTW_PCI_RX_BD_SIZE];
            rbd[0..2].copy_from_slice(&(RTK_PCI_RX_BUF_SIZE as u16).to_le_bytes());
            rbd[4..8].copy_from_slice(&buf_pa.to_le_bytes());
            dma.write_bytes(self.rx_ring.bd_off + slot * RTW_PCI_RX_BD_SIZE, &rbd);
            self.rx_ring.rp = next_rp;
            mmio.write16(RTK_PCI_RXBD_IDX_MPDUQ, next_rp & 0x0FFF);

            if crc_err || icv_err || pkt_len == 0 || pkt_off + pkt_len > RTK_PCI_RX_BUF_SIZE {
                continue;
            }

            if is_c2h {
                let mut c2h_buf = [0u8; 32];
                let n = pkt_len.min(c2h_buf.len());
                dma.read_bytes(buf_off + pkt_off, &mut c2h_buf[..n]);
                if let Some(slot_out) = c2h_out.as_deref_mut() {
                    *slot_out = Some(parse_c2h_packet(&c2h_buf[..n]));
                }
                continue;
            }

            // Strip trailing 4-byte FCS if hardware appended it (`BIT_APP_FCS`)
            let mpdu_len = if pkt_len > 28 { pkt_len - 4 } else { pkt_len };
            if mpdu_len > out_mpdu.len() {
                continue;
            }
            dma.read_bytes(buf_off + pkt_off, &mut out_mpdu[..mpdu_len]);
            return Some((mpdu_len, rssi_dbm));
        }
        None
    }
}

impl Default for Rtl8821ceHw {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute Realtek 8821C 16-word XOR checksum into `w7[15:0]` (`fill_txdesc_checksum_common`).
pub fn fill_txdesc_checksum_16words(txdesc: &mut [u8; RTW_TX_DESC_SIZE]) {
    txdesc[28] = 0;
    txdesc[29] = 0;
    let mut csum = 0u16;
    for i in 0..16usize {
        let w = u16::from_le_bytes([txdesc[i * 2], txdesc[i * 2 + 1]]);
        csum ^= w;
    }
    let bytes = csum.to_le_bytes();
    txdesc[28] = bytes[0];
    txdesc[29] = bytes[1];
}

#[allow(clippy::too_many_arguments)]
pub fn build_full_tx_desc(
    mpdu_len: u16,
    qsel: u8,
    rate: u8,
    use_rate: bool,
    bmc: bool,
    sec_type: u8,
    seq: u16,
    tim_offset: u8,
    out: &mut [u8; RTW_TX_DESC_SIZE],
) {
    out.fill(0);
    let more_data = qsel == 17;
    let w0 = u32::from(mpdu_len) | (48u32 << 16) | (u32::from(bmc) << 24) | (1u32 << 26); // LS
    let w1 = (u32::from(qsel & 0x1F) << 8)
        | (3u32 << 16) // RATE_ID = BGN_20M_1SS
        | (u32::from(sec_type & 0x03) << 22)
        | (u32::from(more_data) << 29);
    let w3 = (u32::from(use_rate) << 8) | (0x0Fu32 << 17);
    let w4 = u32::from(rate & 0x7F);
    let w8 = 1u32 << 15; // EN_HWSEQ
    let mut w9 = u32::from(seq & 0x0FFF) << 12;
    if tim_offset != 0 {
        w9 |= (1u32 << 7) | u32::from(tim_offset & 0x7F);
    }
    out[0..4].copy_from_slice(&w0.to_le_bytes());
    out[4..8].copy_from_slice(&w1.to_le_bytes());
    out[12..16].copy_from_slice(&w3.to_le_bytes());
    out[16..20].copy_from_slice(&w4.to_le_bytes());
    out[32..36].copy_from_slice(&w8.to_le_bytes());
    out[36..40].copy_from_slice(&w9.to_le_bytes());
    // Note: on Realtek PCIe (`pci.c:829`, `main.h:913`), `w7[15:0]` MUST stay 0
    // (`fill_txdesc_checksum_16words` is strictly USB/SDIO-only).
}

fn decode_8821c_phy_rssi(phy: &[u8; 16], rx_rate: u8, rfe_option: u8) -> i8 {
    let page = phy[0] & 0x0F;
    if page == 0 || rx_rate <= 0x03 {
        const LNA0: [i16; 8] = [22, 8, -6, -22, -31, -40, -46, -52];
        const LNA1: [i16; 16] = [
            10, 6, 2, -2, -6, -10, -14, -17, -20, -24, -28, -31, -34, -37, -40, -44,
        ];
        let dw3 = u32::from_le_bytes([phy[12], phy[13], phy[14], phy[15]]);
        let vga = ((dw3 >> 8) & 0x1F) as i16;
        let lna_l = ((dw3 >> 13) & 0x07) as usize;
        let lna_h = (((dw3 >> 23) & 0x01) as usize) << 3;
        let lna_idx = lna_h | lna_l;
        let gain = if rfe_option == 0 {
            *LNA0.get(lna_idx).unwrap_or(&-40)
        } else {
            *LNA1.get(lna_idx).unwrap_or(&-40)
        };
        (gain - 2 * vga).clamp(-95, -20) as i8
    } else {
        let pwdb_a = i16::from(phy[1]);
        (pwdb_a - 110).clamp(-95, -20) as i8
    }
}

fn parse_c2h_packet(buf: &[u8]) -> RtwC2hEvent {
    if buf.len() < 2 {
        return RtwC2hEvent::Other { cmd_id: 0, seq: 0 };
    }
    let id = buf[0];
    let seq = buf[1];
    let payload = &buf[2..];
    match id {
        0x0C if payload.len() >= 7 => RtwC2hEvent::RaReport {
            rate: payload[0] & 0x7F,
            sgi: (payload[0] & 0x80) != 0,
            mac_id: payload[1],
            bw: payload[6],
        },
        0x03 if payload.len() >= 7 => RtwC2hEvent::TxReport {
            seq_num: payload[6] & 0xFC,
            ok: (payload[0] & 0xC0) == 0,
        },
        _ => RtwC2hEvent::Other { cmd_id: id, seq },
    }
}
