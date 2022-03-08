from videzzo_types_lib import Model
from videzzo_types_lib import FIELD_RANDOM, FIELD_FLAG, FIELD_POINTER, FIELD_CONSTANT
from videzzo_types_lib import dict_append

# id slots
# - audio: 00-09
# - network: 10-39
# - block: 40-69
# - usb: 70-89
# - display: 90-99
# convention
# - Model name: ac97 (all lowercase)
# - field name: AC97_BD (all uppercase)
# - Model buf: AC97_BUF0 (XXX_BUFX)

ac97_00 = Model('ac97', 0)
ac97_00.add_struct('AC97_BD', {'addr#0x4': FIELD_POINTER, 'ctl_len#0x4': FIELD_FLAG})
ac97_00.add_flag('AC97_BD.ctl_len', {0: 16, 16: 14, 30: 1, 31: 1})
ac97_00.add_struct('AC97_BUF0', {'buf#0x1000': FIELD_RANDOM})
ac97_00.add_point_to('AC97_BD.addr', ['AC97_BUF0'], alignment=2)
ac97_00.add_head(['AC97_BD'])
ac97_00.add_instrumentation_point('ac97.c', ['fetch_bd', 'pci_dma_read', 0, 1])
###################################################################################################################
# cs423a uses i8257_dma_read_memory
cs4231a_01 = Model('cs4231a', 1)
cs4231a_01.add_struct('CS4231A_BUF0', {'buf#0x1000': FIELD_RANDOM})
cs4231a_01.add_head(['CS4231A_BUF0'])
cs4231a_01.add_instrumentation_point('cs4231a.c', ['i8257_dma_read_memory', 'cpu_physical_memory_read', 0, 0])
###################################################################################################################
es1370_02 = Model('es1370', 2)
es1370_02.add_struct('ES1370_BUF0', {'buf#0x1000': FIELD_RANDOM})
es1370_02.add_head(['ES1370_BUF0'])
es1370_02.add_instrumentation_point('es1370.c', ['es1370_transfer_audio', 'pci_dma_read', 0, 1])
###################################################################################################################
intel_hda_03 = Model('intel_hda', 3)
intel_hda_03.add_struct('INTEL_HDA_BUF0', {'addr#0x8': FIELD_POINTER, 'len#0x4': FIELD_RANDOM, 'flags#0x4': FIELD_FLAG})
intel_hda_03.add_struct('INTEL_HDA_BUF1', {'buf#0x1000': FIELD_RANDOM})
intel_hda_03.add_point_to('INTEL_HDA_BUF0.addr', ['INTEL_HDA_BUF1'])
intel_hda_03.add_flag('INTEL_HDA_BUF0.flags', {0: 1, 1: 31})
intel_hda_03.add_head(['INTEL_HDA_BUF0'])
intel_hda_03.add_instrumentation_point('intel-hda.c', ['intel_hda_parse_bdl', 'pci_dma_read', 0, 1])
###################################################################################################################
intel_hda_04 = Model('intel_hda', 4)
intel_hda_04.add_struct('INTEL_HDA_VERB', {'verb#0x4': FIELD_FLAG})
intel_hda_04.add_flag('INTEL_HDA_VERB.verb', {0: 8, 8: 12, 20: 7, 27: 1, 28: 4})
intel_hda_04.add_head(['INTEL_HDA_VERB'])
intel_hda_04.add_instrumentation_point('intel-hda.c', ['intel_hda_corb_run', 'ldl_le_pci_dma', 0, 1])
###################################################################################################################
# sb16 also uses i8257_dma_read_memory but we only instrument once
sb16_05 = Model('sb16', 5)
sb16_05.add_struct('SB16_BUF0', {'buf#0x1000': FIELD_RANDOM})
sb16_05.add_head(['SB16_BUF0'])
sb16_05.add_instrumentation_point('i8257.c', ['i8257_dma_read_memory', 'cpu_physical_memory_read', 0, 0])
###################################################################################################################
eepro100_10 = Model('eepro100', 10)
eepro100_tx = {
    'status#0x2': FIELD_FLAG, 'command#0x2': FIELD_FLAG, 'link#0x4': FIELD_RANDOM,
    'tbd_array_addr#0x4': FIELD_POINTER,
    'tcb_bytes#0x2': FIELD_RANDOM, 'tx_threshold#0x1': FIELD_RANDOM, 'tbd_count#0x1': FIELD_RANDOM,
    'tx_buf_addr0#0x4': FIELD_POINTER, 'tx_buf_size0#0x4': FIELD_FLAG,
    'tx_buf_addr1#0x4': FIELD_POINTER, 'tx_buf_size1#0x4': FIELD_FLAG,
}
eepro100_10.add_struct('EEPRO100_TX', eepro100_tx)
eepro100_10.add_flag('EEPRO100_TX.status', {0: 13, 13: 1, 14: 1, 15: 1})
eepro100_10.add_flag('EEPRO100_TX.command', {0: 3, 3: 1, 4: 1, 5: 8, 13: 1, 14: 1, 15: 1})
eepro100_10.add_flag('EEPRO100_TX.tx_buf_size0', {0: 16, 16: 16})
eepro100_10.add_flag('EEPRO100_TX.tx_buf_size1', {0: 16, 16: 16})
# utils
mac_addr = {
    'mac_addr0#0x1': FIELD_RANDOM, 'mac_addr1#0x1': FIELD_RANDOM, 'mac_addr2#0x1': FIELD_RANDOM,
    'mac_addr3#0x1': FIELD_RANDOM, 'mac_addr4#0x1': FIELD_RANDOM, 'mac_addr5#0x1': FIELD_RANDOM}
eepro100_10.add_struct('EEPRO100_TX_BUF', {'buf#0xa28': FIELD_RANDOM})
# switch-case-1
eepro100_10.add_struct('MAC_ADDR0', mac_addr)
# switch-case-2
eepro100_configuration = {}
for i in range(0, 22):
    eepro100_configuration['configuration{}#0x1'.format(i)] = FIELD_FLAG
eepro100_10.add_struct('CONFIGURATION', eepro100_configuration)
for i in range(0, 22):
    eepro100_10.add_flag('CONFIGURATION.configuration{}'.format(i), {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1})
# switch-case-3
# we handle pointer:data union (un-fusable) as a second buffer: under-approximation
eepro100_11 = Model('eepro100', 11)
eepro100_11.add_struct('MAC_ADDR1', mac_addr)
eepro100_11.add_head(['MAC_ADDR1'])
eepro100_11.add_instrumentation_point('eepro100.c', ['set_multicast_list', 'pci_dma_read', 0, 1])
# switch-case-4
eepro100_10.add_struct('TX_BUFFER', {
    'tx_buf_addr#0x4': FIELD_POINTER, 'tx_buf_size#0x2': FIELD_RANDOM, 'tx_buf_el#0x2': FIELD_RANDOM})
eepro100_10.add_point_to('TX_BUFFER.tx_buf_addr', ['EEPRO100_TX_BUF'])
eepro100_10.add_point_to('EEPRO100_TX.tx_buf_addr0', ['TX_BUFFER'])
eepro100_10.add_point_to('EEPRO100_TX.tx_buf_addr1', ['TX_BUFFER'])
# the most interesting part: switch case
eepro100_10.add_point_to('EEPRO100_TX.tbd_array_addr', [
    'EEPRO100_TX_BUF', # 0
    'MAC_ADDR0', # 1
    'CONFIGURATION', # 2
    'EEPRO100_TX_BUF', # 3
    'TX_BUFFER', # 4
    'EEPRO100_TX_BUF', # 5
    'EEPRO100_TX_BUF', # 6
    'EEPRO100_TX_BUF', # 7
], flags=['EEPRO100_TX.command.0'])
eepro100_10.add_head(['EEPRO100_TX'])
eepro100_10.add_instrumentation_point('eepro100.c', ['read_cb', 'pci_dma_read', 0, 1])
###################################################################################################################
# eepro100 has a wierd operation in eepro100_write_port, which is not necessary to be instrumented
###################################################################################################################
eepro100_12 = Model('eepro100', 12)
eepro100_rx = {
    'status#0x2': FIELD_FLAG, 'command#0x2': FIELD_FLAG, 'link#0x4': FIELD_RANDOM,
    'rx_buf_addr#0x4': FIELD_POINTER, 'count#0x2': FIELD_RANDOM, 'size#0x2': FIELD_RANDOM}
eepro100_12.add_struct('EEPRO100_RX', eepro100_rx)
eepro100_12.add_flag('EEPRO100_RX.status', {0: 13, 13: 1, 14: 1, 15: 1})
eepro100_12.add_flag('EEPRO100_RX.command', {0: 3, 3: 1, 4: 1, 5: 8, 13: 1, 14: 1, 15: 1})
eepro100_12.add_struct('EEPRO100_RX_BUF', {'buf#0x1000': FIELD_RANDOM})
eepro100_12.add_point_to('EEPRO100_RX.rx_buf_addr', ['EEPRO100_RX_BUF'])
eepro100_12.add_head(['EEPRO100_RX'])
eepro100_12.add_instrumentation_point('eepro100.c', ['nic_receive', 'pci_read_dma', 0, 1])
###################################################################################################################
# utils
# we handle random:flag union as a flag: under-approximation
e1000_tx_desc = {'buffer_addr#0x8': FIELD_POINTER, 'flags#0x4': FIELD_FLAG, 'fields#0x4': FIELD_FLAG}
###################################################################################################################
# for e1000e, you have to carefully search via read/dma key words
e1000e_13 = Model('e1000e', 13)
e1000e_13.add_struct('E1000_TX_DESC0', e1000_tx_desc)
# it's not necessary to handle e1000x_read_tx_ctx_descr
e1000e_13.add_flag('E1000_TX_DESC0.flags', {
    0: 16, 16: 4, 20: 1, 21: 3, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
e1000e_13.add_flag('E1000_TX_DESC0.fields', {0: 16, 16: 8, 24: 16})
e1000e_13.add_struct('E1000E_BUF0', {'buf#0x10000': FIELD_RANDOM})
e1000e_13.add_point_to('E1000_TX_DESC0.buffer_addr', ['E1000E_BUF0'])
e1000e_13.add_head(['E1000_TX_DESC0'])
e1000e_13.add_instrumentation_point('e1000e_core.c', ['e1000e_start_xmit', 'pci_dma_read', 0, 1])
###################################################################################################################
e1000e_14 = Model('e1000e', 14)
# quite complicated: e1000e_read_rx_descr, e1000_rx_desc_packet_split, e1000_rx_desc_extended
# buffer_addr works for e1000e_read_rx_descr (under-but-exact-approximation)
e1000e_14.add_struct('DESC', {'buffer_addr#0x8': FIELD_POINTER})
e1000e_14.add_struct('E1000E_BUF1', {'buf#0x1000': FIELD_RANDOM})
e1000e_14.add_point_to('DESC.buffer_addr', ['E1000E_BUF1'])
e1000e_14.add_head(['DESC'])
e1000e_14.add_instrumentation_point('e1000e_core.c', ['e1000e_write_packet_to_guest', 'pci_dma_read', 0, 1])
###################################################################################################################
e1000_15 = Model('e1000', 15)
e1000_15.add_struct('E1000_TX_DESC1', e1000_tx_desc)
# it's not necessary to handle e1000x_read_tx_ctx_descr
e1000_15.add_flag('E1000_TX_DESC1.flags', {
    0: 16, 16: 4, 20: 1, 21: 3, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
e1000_15.add_flag('E1000_TX_DESC1.fields', {0: 16, 16: 8, 24: 16})
e1000_15.add_struct('E1000_BUF0', {'buf#0x10000': FIELD_RANDOM})
e1000_15.add_point_to('E1000_TX_DESC1.buffer_addr', ['E1000_BUF0'])
e1000_15.add_head(['E1000_TX_DESC1'])
e1000_15.add_instrumentation_point('e1000.c', ['start_xmit', 'pci_dma_read', 0, 1])
###################################################################################################################
e1000_16 = Model('e1000', 16)
e1000_16.add_struct('E1000_RX_DESC', {
    'buffer_addr#0x8': FIELD_POINTER,
    'length#0x2': FIELD_RANDOM, 'csum#0x2': FIELD_RANDOM, 'status#0x1': FIELD_FLAG, 'errors#0x1': FIELD_RANDOM, 'special#0x2': FIELD_FLAG})
e1000_16.add_flag('E1000_RX_DESC.status', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1})
e1000_16.add_flag('E1000_RX_DESC.special', {0: 12, 12: 1, 13: 3})
e1000_16.add_struct('E1000_BUF1', {'buf#0x10000': FIELD_RANDOM})
e1000_16.add_point_to('E1000_RX_DESC.buffer_addr', ['E1000_BUF1'])
e1000_16.add_head(['E1000_RX_DESC'])
e1000_16.add_instrumentation_point('e1000.c', ['e1000_receive_iov', 'pci_dma_read', 0, 1])
###################################################################################################################
# ne2000 maintaining an internal mem buffer does have any dma accesses
###################################################################################################################
pcnet_17 = Model('pcnet', 17)
pcnet_17.add_struct('PCNET_XDA', {'tbadr#0x4': FIELD_POINTER | FIELD_FLAG, 'length#0x2': FIELD_RANDOM, 'status#0x2': FIELD_FLAG})
pcnet_17.add_flag('PCNET_XDA.tbadr', {24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
pcnet_17.add_flag('PCNET_XDA.status', {0: 10, 10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 15: 1})
pcnet_17.add_struct('PCNET_BUF0', {'buf#0x1000': FIELD_RANDOM})
pcnet_17.add_point_to('PCNET_XDA.tbadr', ['PCNET_BUF0'])
pcnet_17.add_head(['PCNET_XDA'])
pcnet_17.add_instrumentation_point('pcnet.c', ['pcnet_tmd_load', 'phys_mem_read', 0, 1])
###################################################################################################################
pcnet_18 = Model('pcnet', 18)
pcnet_18.add_struct('PCNET_TMD', {'tbadr#0x4': FIELD_POINTER, 'length#0x2': FIELD_RANDOM, 'status#0x2': FIELD_FLAG, 'misc#0x4': FIELD_FLAG, 'res#0x4': FIELD_RANDOM})
pcnet_18.add_flag('PCNET_TMD.status', {0: 7, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 15: 1, 16: 16})
pcnet_18.add_flag('PCNET_TMD.misc', {0: 4, 4: 12, 16: 10, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
pcnet_18.add_struct('PCNET_BUF1', {'buf#0x1000': FIELD_RANDOM})
pcnet_18.add_point_to('PCNET_TMD.tbadr', ['PCNET_BUF1'])
# pcnet_tmd_load: 321 to 325: this union needs extra hackings! under approximation
pcnet_18.add_head(['PCNET_TMD'])
pcnet_18.add_instrumentation_point('pcnet.c', ['pcnet_tmd_load', 'phys_mem_read', 1, 1])
###################################################################################################################
pcnet_19 = Model('pcnet', 19)
pcnet_19.add_struct('PCNET_RDA', {'rbadr#0x4': FIELD_POINTER | FIELD_FLAG, 'buf_length#0x2': FIELD_RANDOM, 'msg_length#0x2': FIELD_FLAG})
pcnet_19.add_flag('PCNET_RDA.rbadr', {24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
pcnet_19.add_flag('PCNET_RDA.msg_length', {0: 12, 12: 4})
pcnet_19.add_struct('PCNET_BUF2', {'buf#0x1000': FIELD_RANDOM})
pcnet_19.add_point_to('PCNET_RDA.rbadr', ['PCNET_BUF2'])
pcnet_19.add_head(['PCNET_RDA'])
pcnet_19.add_instrumentation_point('pcnet.c', ['pcnet_rmd_load', 'phys_mem_read', 0, 1])
###################################################################################################################
pcnet_20 = Model('pcnet', 20)
pcnet_20.add_struct('PCNET_RMD', {'rbadr#0x4': FIELD_POINTER, 'buf_length#0x2': FIELD_RANDOM, 'status#0x2': FIELD_FLAG, 'msg_length#0x4': FIELD_FLAG, 'res#0x4': FIELD_RANDOM})
pcnet_20.add_flag('PCNET_RMD.status', {0: 4, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 15: 1, 16: 16})
pcnet_20.add_flag('PCNET_RMD.msg_length', {0: 12, 12: 4, 16: 8, 24: 8})
pcnet_20.add_struct('PCNET_BUF3', {'buf#0x1000': FIELD_RANDOM})
pcnet_20.add_point_to('PCNET_RMD.rbadr', ['PCNET_BUF3'])
# pcnet_tmd_load: 390 to 394: this union needs extra hackings! under approximation
pcnet_20.add_head(['PCNET_RMD'])
pcnet_20.add_instrumentation_point('pcnet.c', ['pcnet_rmd_load', 'phys_mem_read', 1, 1])
###################################################################################################################
pcnet_21 = Model('pcnet', 21)
pcnet_21.add_struct('PCNET_INITBLK32', {
    'mode#0x2': FIELD_FLAG, 'rlen#0x1': FIELD_FLAG, 'tlen#0x1': FIELD_FLAG,
    'padrf0#0x2': FIELD_FLAG, 'padrf1#0x2': FIELD_FLAG, 'padrf2#0x2': FIELD_FLAG, '_res#0x2': FIELD_RANDOM,
    'ladrf0#0x2': FIELD_FLAG, 'ladrf1#0x2': FIELD_FLAG, 'ladrf2#0x2': FIELD_FLAG, 'ladrf3#0x2': FIELD_FLAG,
    'rdra#0x4': FIELD_RANDOM, 'tdra#0x4': FIELD_RANDOM})
pcnet_21.add_flag('PCNET_INITBLK32.mode', {0: 1, 1: 1, 2: 1, 3: 1, 4: 2, 6: 1, 7: 6, 13: 1, 14: 1, 15: 1})
pcnet_21.add_flag('PCNET_INITBLK32.rlen', {0: 4, 4: 4})
pcnet_21.add_flag('PCNET_INITBLK32.tlen', {0: 4, 4: 4})
pcnet_21.add_flag('PCNET_INITBLK32.padrf0', {0: 8, 8: 8})
pcnet_21.add_flag('PCNET_INITBLK32.padrf1', {0: 8, 8: 8})
pcnet_21.add_flag('PCNET_INITBLK32.padrf2', {0: 8, 8: 8})
pcnet_21.add_flag('PCNET_INITBLK32.ladrf0', {0: 8, 8: 8})
pcnet_21.add_flag('PCNET_INITBLK32.ladrf1', {0: 8, 8: 8})
pcnet_21.add_flag('PCNET_INITBLK32.ladrf2', {0: 8, 8: 8})
pcnet_21.add_flag('PCNET_INITBLK32.ladrf3', {0: 8, 8: 8})
pcnet_21.add_head(['PCNET_INITBLK32'])
pcnet_21.add_instrumentation_point('pcnet.c', ['pcnet_init', 'phys_mem_read', 0, 1])
###################################################################################################################
pcnet_22 = Model('pcnet', 22)
pcnet_22.add_struct('PCNET_INITBLK16', {
    'mode#0x2': FIELD_FLAG, 'padrf0#0x2': FIELD_RANDOM, 'padrf1#0x2': FIELD_RANDOM, 'padrf2#0x2': FIELD_RANDOM,
    'ladrf0#0x2': FIELD_RANDOM, 'ladrf1#0x2': FIELD_RANDOM, 'ladrf2#0x2': FIELD_RANDOM, 'ladrf3#0x2': FIELD_RANDOM,
    'rdra#0x4': FIELD_FLAG, 'tdra#0x4': FIELD_FLAG})
pcnet_22.add_flag('PCNET_INITBLK16.mode', {0: 1, 1: 1, 2: 1, 3: 1, 4: 2, 6: 1, 7: 6, 13: 1, 14: 1, 15: 1})
pcnet_22.add_flag('PCNET_INITBLK16.rdra', {0: 29, 29: 3})
pcnet_22.add_flag('PCNET_INITBLK16.tdra', {0: 29, 29: 3})
pcnet_22.add_flag('PCNET_INITBLK16.padrf0', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.padrf1', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.padrf2', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.ladrf0', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.ladrf1', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.ladrf2', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.ladrf3', {0: 8, 8: 8})
pcnet_22.add_head(['PCNET_INITBLK16'])
pcnet_22.add_instrumentation_point('pcnet.c', ['pcnet_init', 'phys_mem_read', 1, 1])
###################################################################################################################
pcnet_23 = Model('pcnet', 23)
pcnet_23.add_struct('PCNET_BUF4', {'buf#0x1000': FIELD_RANDOM})
# point-to dependency with complicated constraits: cannot support PHYSADDR
pcnet_23.add_head(['PCNET_BUF4'])
pcnet_23.add_instrumentation_point('pcnet.c', ['pcnet_transmit', 'phys_mem_read', 0, 1])
###################################################################################################################
rtl8139_24 = Model('rtl8139', 24)
rtl8139_24.add_struct('RTL8139_RX_RING_DESC', {
    'rxdw0#0x4': FIELD_FLAG, 'rxdw1#0x4': FIELD_FLAG, 'rxbuf#0x8': FIELD_POINTER})
rtl8139_24.add_flag('RTL8139_RX_RING_DESC.rxdw0', {0: 13, 13: 1, 14: 1, 15: 1, 16: 1, 17: 1, 18: 1, 19: 1, 20: 4, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
rtl8139_24.add_flag('RTL8139_RX_RING_DESC.rxdw1', {0: 13, 13: 1, 14: 1, 15: 1, 16: 1, 17: 1, 18: 1, 19: 1, 20: 4, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
rtl8139_24.add_struct('RTL8139_RX_RING_DESC_BUF', {'buf#0x1000': FIELD_RANDOM})
rtl8139_24.add_point_to('RTL8139_RX_RING_DESC.rxbuf', ['RTL8139_RX_RING_DESC_BUF'])
rtl8139_24.add_head(['RTL8139_RX_RING_DESC'])
rtl8139_24.add_instrumentation_point('rtl8139.c', ['rtl8139_do_receive', 'pci_dma_read', 0, 1])
###################################################################################################################
rtl8139_25 = Model('rtl8139', 25)
rtl8139_25.add_struct('RTL8139_BUF', {'buf#0x2000': FIELD_RANDOM})
rtl8139_25.add_head(['RTL8139_BUF'])
rtl8139_25.add_instrumentation_point('rtl8139.c', ['rtl8139_transmit_one', 'pci_dam_read', 0, 1])
###################################################################################################################
rtl8139_26 = Model('rtl8139', 26)
rtl8139_26.add_struct('RTL8139_TX_RING_DESC', {
    'txdw0#0x4': FIELD_FLAG, 'txdw1#0x4': FIELD_FLAG, 'txbuf#0x8': FIELD_POINTER})
rtl8139_26.add_flag('RTL8139_TX_RING_DESC.txdw0', {0: 16, 16: 1, 17: 1, 18: 9, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
rtl8139_26.add_flag('RTL8139_TX_RING_DESC.txdw1', {0: 16, 16: 1, 17: 1, 18: 14})
rtl8139_26.add_struct('RTL8139_TX_RING_DESC_BUF', {'buf#0x1000': FIELD_RANDOM})
rtl8139_26.add_point_to('RTL8139_TX_RING_DESC.txbuf', ['RTL8139_TX_RING_DESC_BUF'])
rtl8139_26.add_head(['RTL8139_TX_RING_DESC'])
rtl8139_26.add_instrumentation_point('rtl8139.c', ['rtl8139_cplus_transmit_one', 'pci_dma_read', 0, 1])
###################################################################################################################
vmxnet3_27 = Model('vmxnet3', 27)
# part 1
# union: compilation flag: choose little end
vmxnet3_27.add_struct('Vmxnet3_TxDesc', {'addr#0x8': FIELD_POINTER, 'val1#0x4': FIELD_FLAG, 'val2#0x4': FIELD_FLAG})
vmxnet3_27.add_struct('Vmxnet3_TxDesc_Buf', {'buf#0x4000': FIELD_RANDOM})
vmxnet3_27.add_point_to('Vmxnet3_TxDesc.addr', ['Vmxnet3_TxDesc_Buf'])
vmxnet3_27.add_flag('Vmxnet3_TxDesc.val1', {0: 14, 14: 1, 15: 1, 16: 1, 17: 1, 18: 14})
vmxnet3_27.add_flag('Vmxnet3_TxDesc.val2', {0: 10, 10: 2, 12: 1, 13: 1, 14: 1, 15: 1, 16: 16})
vmxnet3_27.add_struct('Vmxnet3_TxCompDesc', {'val1#0x4': FIELD_FLAG, 'ext2#0x4': FIELD_RANDOM, 'ext3#0x4': FIELD_RANDOM, 'val2#0x4': FIELD_FLAG})
vmxnet3_27.add_flag('Vmxnet3_TxCompDesc.val1', {0: 12, 12: 20})
vmxnet3_27.add_flag('Vmxnet3_TxCompDesc.val2', {0: 24, 24: 7, 31: 1})
Vmxnet3_TxQueueDesc = {
    # Vmxnet3_TxQueueCtrl
    'txNumDeferred#0x4': FIELD_RANDOM, 'txThreshold#0x4': FIELD_RANDOM, 'reserved_0#0x8': FIELD_RANDOM,
    # Vmxnet3_TxQueueConf
    'txRingBasePA#0x8': FIELD_POINTER, 'dataRingBasePA#0x8': FIELD_RANDOM, # dataRingBasePA never used
    'compRingBasePA#0x8': FIELD_POINTER, 'ddPA#0x8': FIELD_RANDOM, 'reserved_1#0x8': FIELD_RANDOM,
    'txRingSize#0x4': FIELD_RANDOM, 'dataRingSize#0x4': FIELD_RANDOM, 'compRingSize#0x4': FIELD_RANDOM,
    'ddLen#0x4': FIELD_RANDOM, 'intrIdx#0x1': FIELD_RANDOM, '_pad_0#0x7': FIELD_RANDOM,
    # Vmxnet3_QueueStatus
    'stopped#0x1': FIELD_RANDOM, '_pad_1#0x3': FIELD_RANDOM, 'reserved_2#0x8': FIELD_RANDOM,
    # UPT1_RxStats
    'LROPktsRxOK#0x8': FIELD_RANDOM, 'LROBytesRxOK#0x8': FIELD_RANDOM, 'ucastPktsRxOK#0x8': FIELD_RANDOM, 'ucastBytesRxOK#0x8': FIELD_RANDOM,
    'mcastPktsRxOK#0x8': FIELD_RANDOM, 'mcastBytesRxOK#0x8': FIELD_RANDOM, 'bcastPktsRxOK#0x8': FIELD_RANDOM, 'bcastBytesRxOK#0x8': FIELD_RANDOM,
    'pktsRxOutOfBuf#0x8': FIELD_RANDOM, 'pktsRxError#0x8': FIELD_RANDOM,
    # pad
    '_pad_2#0x88': FIELD_RANDOM}
vmxnet3_27.add_struct('Vmxnet3_TxQueueDesc', Vmxnet3_TxQueueDesc)
vmxnet3_27.add_point_to('Vmxnet3_TxQueueDesc.txRingBasePA', ['Vmxnet3_TxDesc'], array=True)
vmxnet3_27.add_point_to('Vmxnet3_TxQueueDesc.compRingBasePA', ['Vmxnet3_TxCompDesc'], array=True)
vmxnet3_27.add_struct('Vmxnet3_MACADDR', {'addr0#0x1': FIELD_RANDOM, 'addr1#0x1': FIELD_RANDOM, 'addr2#0x1': FIELD_RANDOM,
                                          'addr3#0x1': FIELD_RANDOM, 'addr4#0x1': FIELD_RANDOM, 'addr5#0x1': FIELD_RANDOM})
# part 2
Vmxnet3_DriverShared = {
    # Vmxnet3_DriverShared_p1
    'magic#0x4': FIELD_CONSTANT, 'pad_3#0x4': FIELD_RANDOM,
    # Vmxnet3_DSDevRead
        # Vmxnet3_MiscConf
        # Vmxnet3_DriverInfo
        'version#0x4': FIELD_RANDOM, 'gos#0x4': FIELD_FLAG, 'vmxnet3RevSpt#0x4': FIELD_RANDOM, 'uptVerSpt#0x4': FIELD_RANDOM,
        # Vmxnet3_MiscConf_p1
        'uptFeature#0x8': FIELD_RANDOM, 'ddPA#0x8': FIELD_RANDOM, 'queueDescPA#0x8': FIELD_POINTER, 'ddLen#0x4': FIELD_RANDOM,
        'queueDescLen#0x4': FIELD_RANDOM, 'mtu#0x4': FIELD_RANDOM, 'maxNumRxSG#0x2': FIELD_RANDOM, 'numTxQueues#0x1': FIELD_RANDOM,
        'numRxQueues#0x1': FIELD_RANDOM, 'reserved_3#0x10': FIELD_RANDOM,
        # Vmxnet3_IntrConf
        'autoMask#0x1': FIELD_RANDOM, 'numIntrs#0x1': FIELD_RANDOM, 'eventIntrIdx#0x1': FIELD_RANDOM, 'modLevels#0x19': FIELD_RANDOM,
        'intrCtrl#0x4': FIELD_RANDOM, 'reserved_4#0x8': FIELD_RANDOM,
        # Vmxnet3_RxFilterConf
        'rxMode#0x4': FIELD_RANDOM, 'mfTableLen#0x2': FIELD_RANDOM, '_pad_4#0x2': FIELD_RANDOM, 'mfTablePA#0x8': FIELD_POINTER, 'vfTable#0x2000': FIELD_RANDOM,
        # Vmxnet3_VariableLenConfDesc0
        'confVer_0#0x4': FIELD_RANDOM, 'confLen_0#0x4': FIELD_RANDOM, 'confPA_0#0x8': FIELD_RANDOM, # confPA is never used
        # Vmxnet3_VariableLenConfDesc1
        'confVer_1#0x4': FIELD_RANDOM, 'confLen_1#0x4': FIELD_RANDOM, 'confPA_1#0x8': FIELD_RANDOM, # confPA is never used
        # Vmxnet3_VariableLenConfDesc2
        'confVer_2#0x4': FIELD_RANDOM, 'confLen_2#0x4': FIELD_RANDOM, 'confPA_2#0x8': FIELD_RANDOM, # confPA is never used
    # Vmxnet3_DriverShared_p2
    'ecr#0x4': FIELD_RANDOM, 'reserved_5#0x14': FIELD_RANDOM
}
vmxnet3_27.add_struct('Vmxnet3_DriverShared', Vmxnet3_DriverShared)
vmxnet3_27.add_flag('Vmxnet3_DriverShared.gos', {0: 2, 2: 4, 6: 16, 22: 10})
vmxnet3_27.add_constant('Vmxnet3_DriverShared.magic', [0xbabefee1])
vmxnet3_27.add_point_to('Vmxnet3_DriverShared.queueDescPA', ['Vmxnet3_TxQueueDesc'], array=True)
vmxnet3_27.add_point_to('Vmxnet3_DriverShared.mfTablePA', ['Vmxnet3_MACADDR'], array=True)
vmxnet3_27.add_head(['Vmxnet3_DriverShared'])
vmxnet3_27.add_instrumentation_point('vmxnet3.c', ['vmxnet3_activate_device', 'vmxnet3_verify_driver_magic', 0, 1])
###################################################################################################################
# floppy also uses i8257_dma_read_memory but we only instrument once
floppy_40 = Model('floppy', 40)
floppy_40.add_struct('FLOPPY_BUF', {'buf#0x1000': FIELD_RANDOM})
floppy_40.add_head(['FLOPPY_BUF'])
floppy_40.add_instrumentation_point('i8257.c', ['i8257_dma_read_memory', 'cpu_physical_memory_read', 0, 0])
###################################################################################################################
nvme_41 = Model('nvme', 41)
# type fusion with complicated constraits: cannot tell io or admin command
# we also have a sub-type-fusion and we try to do a under-proximitation
nvme_41.add_struct('NvmeCmd', {
    'opcode#0x1': FIELD_CONSTANT, 'fuse#0x1': FIELD_RANDOM, 'cid#0x2': FIELD_RANDOM, 'nsid#0x4': FIELD_RANDOM,
    'res1#0x8': FIELD_RANDOM, 'mptr#0x8': FIELD_POINTER, 'prp1#0x8': FIELD_POINTER, 'prp2#0x8': FIELD_RANDOM,
    'cdw10#0x4': FIELD_RANDOM, 'cdw11#0x4': FIELD_RANDOM, 'cdw12#0x4': FIELD_RANDOM,
    'cdw13#0x4': FIELD_RANDOM, 'cdw14#0x4': FIELD_RANDOM, 'cdw15#0x4': FIELD_RANDOM})
nvme_41.add_constant('NvmeCmd.opcode', [0x0, 0x1, 0x2, 0x4, 0x5, 0x6, 0x8, 0x9, 0xc, 0x10, 0x11, 0x80, 0x81, 0x82])
nvme_41.add_struct('NVME_BUF', {'buf#0x1000': FIELD_RANDOM})
nvme_41.add_point_to('NvmeCmd.mptr', ['NVME_BUF'])
nvme_41.add_point_to('NvmeCmd.prp1', ['NVME_BUF'])
nvme_41.add_point_to('NvmeCmd.prp2', ['NVME_BUF'])
nvme_41.add_head(['NvmeCmd'])
nvme_41.add_instrumentation_point('nvme.c', ['nvme_addr_read', 'pci_dma_read', 0, 1])
###################################################################################################################
# onenand and pflash are also block devices with MemoryRegion
###################################################################################################################
# ahci: we don't ignore this because I realised dma_memory_map is something we should handle!
ahci_42 = Model('ahci', 42)
# the struct is implicity defined
# I'm too lazy: I over-approximate the cmfis#0x1
cmd_fis = {
    'cmfis0#0x1': FIELD_CONSTANT, 'cmfis1#0x1': FIELD_FLAG, 'cmfis2#0x1': FIELD_RANDOM, 'cmfis3#0x1': FIELD_RANDOM,
    'cmfis4#0x8': FIELD_RANDOM,
    'cmfis12#0x1': FIELD_RANDOM, 'cmfis13#0x1': FIELD_RANDOM, 'cmfis14#0x1': FIELD_RANDOM, 'cmfis15#0x1': FIELD_FLAG}
ahci_42.add_struct('AHCI_CMFIS', cmd_fis)
ahci_42.add_constant('AHCI_CMFIS.cmfis0', [0x27, 0x0])
ahci_42.add_flag('AHCI_CMFIS.cmfis1', {0: 4, 4: 3, 7: 1})
ahci_42.add_flag('AHCI_CMFIS.cmfis15', {0: 2, 2: 1, 3: 5})
ahci_42.add_head(['AHCI_CMFIS'])
ahci_42.add_instrumentation_point('ahci.c', ['handle_cmd', 'dma_memory_map', 0, 1])
###################################################################################################################
ahci_43 = Model('ahci', 43)
ahci_43.add_struct('AHCI_SG', {'addr#0x8': FIELD_POINTER, 'reserved#0x4': FIELD_RANDOM, 'flags_size#0x4': FIELD_RANDOM})
ahci_43.add_struct('AHCI_BUF', {'buf#0x1000': FIELD_RANDOM})
ahci_43.add_point_to('AHCI_SG.addr', ['AHCI_BUF'])
ahci_43.add_head(['AHCI_SG'])
ahci_42.add_instrumentation_point('ahci.c', ['ahci_populate_sglist', 'dma_memory_map', 0, 1])
###################################################################################################################
ahci_44 = Model('ahci', 44)
ahci_44.add_struct('AHCI_RESFIS', {'resfix#0x1000': FIELD_RANDOM})
ahci_44.add_head(['AHCI_RESFIS'])
ahci_44.add_instrumentation_point('ahci', ['ahci_map_fis_address', 'map_page', 0, 2])
###################################################################################################################
# This should be connected to 42, but I simplify it.
ahci_45 = Model('ahci', 45)
ahci_45.add_struct('AHCI_LST', {'lst#0x1000': FIELD_RANDOM})
ahci_45.add_head(['AHCI_LST'])
ahci_45.add_instrumentation_point('ahci', ['ahci_map_fis_address', 'map_page', 0, 2])
###################################################################################################################
sdhci_46 = Model('sdhci', 46)
sdhci_46.add_struct('SDHCI_FIFO_BUFFER0', {'buf#0x1000': FIELD_RANDOM})
sdhci_46.add_head(['SDHCI_FIFO_BUFFER0'])
sdhci_46.add_instrumentation_point('sdhci.c', ['sdhci_sdma_transfer_multi_blocks', 'dma_memory_read', 0, 1])
###################################################################################################################
sdhci_47 = Model('sdhci', 47)
sdhci_47.add_struct('SDHCI_FIFO_BUFFER1', {'buf#0x1000': FIELD_RANDOM})
sdhci_47.add_head(['SDHCI_FIFO_BUFFER1'])
sdhci_47.add_instrumentation_point('sdhci.c', ['sdhci_sdma_transfer_single_block', 'dma_memory_read', 0, 1])
###################################################################################################################
sdhci_48 = Model('sdhci', 48)
sdhci_48.add_struct('SDHCI_ADMA2', {'attr#1': FIELD_RANDOM, 'reserved#1': FIELD_RANDOM, 'length#0x2': FIELD_RANDOM, 'addr#0x4': FIELD_POINTER})
sdhci_48.add_struct('SDHCI_ADMA2_BUF', {'buf#0x1000': FIELD_RANDOM})
sdhci_48.add_point_to('SDHCI_ADMA2.addr', ['SDHCI_ADMA2_BUF'])
sdhci_48.add_head(['SDHCI_ADMA2'])
sdhci_48.add_instrumentation_point('sdhci.c', ['get_adma_description', 'dma_memory_read', 0, 1])
###################################################################################################################
sdhci_49 = Model('sdhci', 49)
sdhci_49.add_struct('SDHCI_ADMA1', {'adma1#0x4': FIELD_POINTER | FIELD_FLAG})
sdhci_49.add_flag('SDHCI_ADMA1.adma1', {0: 7})
sdhci_49.add_struct('SDHCI_ADMA1_BUF', {'buf#0x1000': FIELD_RANDOM})
sdhci_49.add_point_to('SDHCI_ADMA1.adma1', ['SDHCI_ADMA1_BUF'], alignment=7)
sdhci_49.add_head(['SDHCI_ADMA1'])
sdhci_49.add_instrumentation_point('sdhci.c', ['get_adma_description', 'dma_memory_read', 1, 1])
###################################################################################################################
sdhci_50 = Model('sdhci', 50)
sdhci_50.add_struct('SDHCI_ADMA2_64', {'attr#1': FIELD_RANDOM, 'reserved#1': FIELD_RANDOM, 'length#0x2': FIELD_RANDOM, 'addr#0x8': FIELD_POINTER})
sdhci_50.add_struct('SDHCI_ADMA2_64_BUF', {'buf#0x1000': FIELD_RANDOM})
sdhci_50.add_point_to('SDHCI_ADMA2_64.addr', ['SDHCI_ADMA2_64_BUF'])
sdhci_50.add_head(['SDHCI_ADMA2_64'])
sdhci_50.add_instrumentation_point('sdhci.c', ['get_adma_description', 'dma_memory_read', 2, 1])
###################################################################################################################
lsi53c895a_51 = Model('lsi53c895a', 51)
lsi53c895a_51.add_struct('LSI53C895A_BUF0', {'buf#0x1000': FIELD_RANDOM})
lsi53c895a_51.add_head(['LSI53C895A_BUF0'])
lsi53c895a_51.add_instrumentation_point('lsi53c895a.c', ['lsi_mem_read', 'address_space_read', 0, 1])
lsi53c895a_51.add_instrumentation_point('lsi53c895a.c', ['lsi_mem_read', 'pci_dma_read', 0, 1])
###################################################################################################################
lsi53c895a_52 = Model('lsi53c895a', 52)
lsi53c895a_52.add_struct('LSI53C895A_BUF1', {'sfbr#0x1': FIELD_RANDOM, 'pad_4#0x1': FIELD_RANDOM, 'reserved_6#0x8': FIELD_RANDOM})
lsi53c895a_52.add_head(['LSI53C895A_BUF1'])
lsi53c895a_52.add_instrumentation_point('lsi53c895a.c', ['lsi_do_command', 'pci_dma_read', 0, 1])
###################################################################################################################
lsi53c895a_53 = Model('lsi53c895a', 53)
lsi53c895a_53.add_struct('LSI53C895A_BUF2', {'sfbr#0x1': FIELD_RANDOM})
lsi53c895a_53.add_head(['LSI53C895A_BUF2'])
lsi53c895a_53.add_instrumentation_point('lsi53c895a.c', ['lsi_get_msgbyte', 'pci_dma_read', 0, 1])
###################################################################################################################
lsi53c895a_54 = Model('lsi53c895a', 54)
lsi53c895a_54.add_struct('LSI53C895A_BUF3', {'dbc#0x4': FIELD_FLAG, 'addr#0x4': FIELD_RANDOM})
lsi53c895a_54.add_flag('LSI53C895A_BUF3.dbc', {0: 8, 8: 2, 10: 6, 16: 8, 24: 8})
lsi53c895a_54.add_head(['LSI53C895A_BUF3'])
lsi53c895a_54.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'pci_dma_read', 0, 1])
###################################################################################################################
lsi53c895a_55 = Model('lsi53c895a', 55)
lsi53c895a_55.add_struct('LSI53C895A_INST', {'inst#0x4': FIELD_FLAG})
# different instructions have differnet formats!!!!
lsi53c895a_55.add_flag('LSI53C895A_INST.inst', {0: 2, 2: 1, 3: 1, 4: 2, 6: 1, 7: 2, 9: 1, 10: 6, 16: 8, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 2})
lsi53c895a_55.add_head(['LSI53C895A_INST'])
lsi53c895a_55.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 0, 1])
###################################################################################################################
lsi53c895a_56 = Model('lsi53c895a', 56)
lsi53c895a_56.add_struct('LSI53C895A_BUF4', {'buf#0x1000': FIELD_RANDOM})
lsi53c895a_56.add_struct('LSI53C895A_BUF5', {'addr#0x4': FIELD_POINTER})
lsi53c895a_56.add_point_to('LSI53C895A_BUF5.addr', ['LSI53C895A_BUF4'])
lsi53c895a_56.add_head(['LSI53C895A_BUF5'])
lsi53c895a_56.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 1, 1])
lsi53c895a_56.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 2, 1])
lsi53c895a_56.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 3, 1])
lsi53c895a_56.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 5, 1])
###################################################################################################################
lsi53c895a_57 = Model('lsi53c895a', 57)
lsi53c895a_57.add_struct('LSI53C895A_ID', {'id#0x4': FIELD_FLAG})
lsi53c895a_57.add_flag('LSI53C895A_ID.id', {0: 2, 2: 1, 3: 1, 4: 2, 6: 1, 7: 2, 9: 1, 10: 6, 16: 4, 20: 4, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 2})
lsi53c895a_57.add_head(['LSI53C895A_ID'])
lsi53c895a_57.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 4, 1])
###################################################################################################################
lsi53c895a_58 = Model('lsi53c895a', 58)
lsi53c895a_58.add_struct('LSI53C895A_DATA', {'data#0x8': FIELD_RANDOM})
lsi53c895a_58.add_head(['LSI53C895A_DATA'])
lsi53c895a_58.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'pci_dma_read', 1, 1])
###################################################################################################################
# conditions are too complext to analyze
megasas_59 = Model('megasas', 59)
megasas_59.add_struct('MEGASAS_REPLY_QUEUE_TAIL', {'reply_qeueu_tail#0x2': FIELD_RANDOM})
megasas_59.add_head(['MEGASAS_REPLY_QUEUE_TAIL'])
megasas_59.add_instrumentation_point('megasas.c', ['megasas_enqueue_frame', 'ldl_le_pci_dma', 0, 1])
megasas_59.add_instrumentation_point('megasas.c', ['megasas_complete_frame', 'ldl_le_pci_dma', 0, 1])
megasas_59.add_instrumentation_point('megasas.c', ['megasas_complete_frame', 'ldl_le_pci_dma', 1, 1])
###################################################################################################################
# we handle this struct-fusion in a smart way
megasas_60 = Model('megasas', 60)
# common header
__mfi_frame_header = {
    'frame_cmd#0x1': FIELD_CONSTANT, 'sense_len#0x1': FIELD_RANDOM, 'cmd_status#0x1': FIELD_RANDOM, 'scsi_status#0x1': FIELD_RANDOM,
    'target_id#0x1': FIELD_RANDOM, 'lun_id#0x1': FIELD_RANDOM, 'cdb_len#0x1': FIELD_RANDOM, 'sge_count#0x1': FIELD_RANDOM,
    'context#0x8': FIELD_RANDOM, 'flags0#0x2': FIELD_FLAG, 'timeout#0x2': FIELD_RANDOM, 'data_len#0x4': FIELD_RANDOM}
# we cannot perfectly analyze union mfi_sgl so we use a under-approximation
# cmd->iov_size -= dma_buf_read((uint8_t *)&fw_time, dcmd_size, &cmd->qsg);
__mfi_sgl = {'addr#0x8': FIELD_RANDOM, 'len#0x4': FIELD_RANDOM, 'flag#0x4': FIELD_RANDOM}
mfi_init_qinfo = {'flags1#0x4': FIELD_FLAG, 'rq_entries#0x4': FIELD_RANDOM, 'rq_addr#0x8': FIELD_RANDOM, 'pi_addr#0x8': FIELD_RANDOM, 'ci_addr#0x8': FIELD_RANDOM}
megasas_60.add_struct('MEGASAS_MFI_INIT_QINFO', mfi_init_qinfo)
megasas_60.add_flag('MEGASAS_MFI_INIT_QINFO.flags1', {0: 1, 1: 1, 2: 30})
# frame_init start
__mfi_frame_init = {'qinfo_new_addr#0x8': FIELD_POINTER, 'qinfo_old_addr#0x8': FIELD_POINTER, 'reserved_7#0x18': FIELD_RANDOM}
mfi_frame_init = {}
for k, v in __mfi_frame_header.items():
    mfi_frame_init[k] = v
for k, v in __mfi_frame_init.items():
    mfi_frame_init[k] = v
megasas_60.add_struct('MEGASAS_MFI_FRAME_INIT', mfi_frame_init)
megasas_60.add_constant('MEGASAS_MFI_FRAME_INIT.frame_cmd', [0])
megasas_60.add_point_to('MEGASAS_MFI_FRAME_INIT.qinfo_new_addr', ['MEGASAS_MFI_INIT_QINFO'])
megasas_60.add_point_to('MEGASAS_MFI_FRAME_INIT.qinfo_old_addr', ['MEGASAS_MFI_INIT_QINFO'])
megasas_60.add_flag('MEGASAS_MFI_FRAME_INIT.flags0', {0: 1, 1: 1, 2: 30})
# frame_init end
# frame_mcmd start
__mfi_frame_dcmd = {'opcode#0x4': FIELD_CONSTANT, 'mbox#0xc': FIELD_RANDOM}
mfi_frame_dcmd = {}
for k, v in __mfi_frame_header.items():
    mfi_frame_dcmd[k] = v
for k, v in __mfi_frame_dcmd.items():
    mfi_frame_dcmd[k] = v
for k, v in __mfi_sgl.items():
    mfi_frame_dcmd[k] = v
megasas_60.add_struct('MEGASAS_MFI_FRAME_DCMD', mfi_frame_dcmd)
megasas_60.add_constant('MEGASAS_MFI_FRAME_DCMD.frame_cmd', [5])
megasas_60.add_flag('MEGASAS_MFI_FRAME_DCMD.flags0', {0: 1, 1: 1, 2: 30})
megasas_60.add_constant('MEGASAS_MFI_FRAME_DCMD.opcode', [
    0x0100e100, 0x01010000, 0x01020100, 0x01020200, 0x01030000, 0x01030100, 0x01030200,
    0x01030300, 0x01030400, 0x01030500, 0x01040100, 0x01040200, 0x01040300, 0x01040400,
    0x01040500, 0x01050000, 0x01060000, 0x01080101, 0x01080102, 0x010c0100, 0x010c0200,
    0x010d0000, 0x010e0201, 0x010e0202, 0x01101000, 0x02010000, 0x02010100, 0x02020000,
    0x02030100, 0x02040100, 0x02070100, 0x02070200, 0x03010000, 0x03010100, 0x03020000,
    0x03030000, 0x03040000, 0x03090000, 0x04010000, 0x04020000, 0x04030000, 0x04060100,
    0x04060400, 0x05010000, 0x05020000, 0x05030000, 0x05050100, 0x08000000, 0x08010100, 0x08010200])
# frame_mcmd end
# frame_abort start
__mfi_frame_abort = {'abort_context#0x8': FIELD_RANDOM, 'abort_mfi_addr#0x8': FIELD_RANDOM, 'reserved1#0x18': FIELD_RANDOM}
mfi_frame_abort = {}
for k, v in __mfi_frame_header.items():
    mfi_frame_abort[k] = v
for k, v in __mfi_frame_abort.items():
    mfi_frame_abort[k] = v
megasas_60.add_struct('MEGASAS_MFI_FRAME_ABORT', mfi_frame_abort)
megasas_60.add_constant('MEGASAS_MFI_FRAME_ABORT.frame_cmd', [6])
megasas_60.add_flag('MEGASAS_MFI_FRAME_ABORT.flags0', {0: 1, 1: 1, 2: 30})
# frame_abort end
# frame_scsi start
megasas_60.add_struct('MEGASAS_MFI_FRAME_SCSI', __mfi_frame_header)
megasas_60.add_constant('MEGASAS_MFI_FRAME_SCSI.frame_cmd', [3, 4])
megasas_60.add_flag('MEGASAS_MFI_FRAME_SCSI.flags0', {0: 1, 1: 1, 2: 30})
# frame_scsi end
# frame_io start
__mfi_frame_io = {'sense_addr#0x8': FIELD_POINTER, 'lba#0x8': FIELD_RANDOM}
mfi_frame_io = {}
for k, v in __mfi_frame_header.items():
    mfi_frame_io[k] = v
for k, v in __mfi_frame_io.items():
    mfi_frame_io[k] = v
for k, v in __mfi_sgl.items():
    mfi_frame_io[k] = v
megasas_60.add_struct('MEGASAS_MFI_FRAME_IO', mfi_frame_io)
megasas_60.add_constant('MEGASAS_MFI_FRAME_IO.frame_cmd', [1, 2])
megasas_60.add_flag('MEGASAS_MFI_FRAME_IO.flags0', {0: 1, 1: 1, 2: 30})
megasas_60.add_struct('MEGASAS_MFI_SENSE_BUF', {'sense_buf#0xfc': FIELD_RANDOM})
megasas_60.add_point_to('MEGASAS_MFI_FRAME_IO.sense_addr', ['MEGASAS_MFI_SENSE_BUF'])
megasas_60.add_head(['MEGASAS_MFI_FRAME_INIT', 'MEGASAS_MFI_FRAME_DCMD', 'MEGASAS_MFI_FRAME_ABORT',
                     'MEGASAS_MFI_FRAME_SCSI', 'MEGASAS_MFI_FRAME_IO'])
megasas_60.add_instrumentation_point('megasas.c', ['megasas_handle_frame', 'megasas_frame_get_context', 0, 1])
###################################################################################################################
# type = 11: xhci_address_slot
xhci_70 = Model('xhci', 70)
xhci_70.add_struct('ictrl_ctx11', {
    'ictrl_ctx0#0x4': FIELD_CONSTANT, 'ictrl_ctx1#0x4': FIELD_CONSTANT, 'reserved#0x24': FIELD_RANDOM,
    'slot_ctx0#0x4': FIELD_FLAG, 'slot_ctx1#0x4': FIELD_FLAG, 'slot_ctx2#0x4': FIELD_FLAG, 'slot_ctx3#0x4': FIELD_FLAG, 'reserved#0x10': FIELD_RANDOM,
    'ep0_ctx0#0x4': FIELD_RANDOM, 'ep0_ctx1#0x4': FIELD_RANDOM, 'ep0_ctx2#0x4': FIELD_RANDOM, 'ep0_ctx3#0x4': FIELD_RANDOM, 'ep0_ctx4#0x4': FIELD_RANDOM})
xhci_70.add_constant('ictrl_ctx11.ictrl_ctx0', [0])
xhci_70.add_constant('ictrl_ctx11.ictrl_ctx1', [3])
xhci_70.add_flag('ictrl_ctx11.slot_ctx0', {0: 4, 8: 4, 12: 4, 16: 4, 20: 4, 24: 8})
xhci_70.add_flag('ictrl_ctx11.slot_ctx1', {0: 16, 16: 8, 24: 8})
xhci_70.add_flag('ictrl_ctx11.slot_ctx2', {0: 22, 22: 10})
xhci_70.add_flag('ictrl_ctx11.slot_ctx3', {0: 27, 27: 5})
# type = 12: xhci_configure_slot
xhci_70.add_struct('ictrl_ctx12', {
    'ictrl_ctx0#0x4': FIELD_FLAG, 'ictrl_ctx1#0x4': FIELD_FLAG, 'reserved#0x24': FIELD_RANDOM,
    'islot_ctx0#0x4': FIELD_RANDOM, 'islot_ctx1#0x4': FIELD_RANDOM, 'islot_ctx2#0x4': FIELD_RANDOM, 'islot_ctx3#0x4': FIELD_RANDOM, 'reserved#0x10': FIELD_RANDOM,
    'ep_ctx0#0x20': FIELD_RANDOM, 'ep_ctx1#0x20': FIELD_RANDOM, 'ep_ctx2#0x20': FIELD_RANDOM, 'ep_ctx3#0x20': FIELD_RANDOM, 'ep_ctx4#0x20': FIELD_RANDOM,
    'ep_ctx5#0x20': FIELD_RANDOM, 'ep_ctx6#0x20': FIELD_RANDOM, 'ep_ctx7#0x20': FIELD_RANDOM, 'ep_ctx8#0x20': FIELD_RANDOM, 'ep_ctx9#0x20': FIELD_RANDOM,
    'ep_ctx10#0x20': FIELD_RANDOM, 'ep_ctx11#0x20': FIELD_RANDOM, 'ep_ctx12#0x20': FIELD_RANDOM, 'ep_ctx13#0x20': FIELD_RANDOM, 'ep_ctx14#0x20': FIELD_RANDOM,
    'ep_ctx15#0x20': FIELD_RANDOM, 'ep_ctx16#0x20': FIELD_RANDOM, 'ep_ctx17#0x20': FIELD_RANDOM, 'ep_ctx18#0x20': FIELD_RANDOM, 'ep_ctx19#0x20': FIELD_RANDOM,
    'ep_ctx20#0x20': FIELD_RANDOM, 'ep_ctx21#0x20': FIELD_RANDOM, 'ep_ctx22#0x20': FIELD_RANDOM, 'ep_ctx23#0x20': FIELD_RANDOM, 'ep_ctx24#0x20': FIELD_RANDOM,
    'ep_ctx25#0x20': FIELD_RANDOM, 'ep_ctx26#0x20': FIELD_RANDOM, 'ep_ctx27#0x20': FIELD_RANDOM, 'ep_ctx28#0x20': FIELD_RANDOM, 'ep_ctx29#0x20': FIELD_RANDOM})
xhci_70.add_flag('ictrl_ctx12.ictrl_ctx0', {0: '2@3', 2: 30})
xhci_70.add_flag('ictrl_ctx12.ictrl_ctx1', {0: '2@3', 2: 30})
# type = 13: xhci_evaluate_slot: 13
xhci_70.add_struct('ictrl_ctx13', {
    'ictrl_ctx0#0x4': FIELD_CONSTANT, 'ictrl_ctx1#0x4': FIELD_FLAG, 'reserved#0x24': FIELD_RANDOM,
    'islot_ctx#0x20': FIELD_RANDOM, 'ep0_ctx#0x20': FIELD_RANDOM})
xhci_70.add_constant('ictrl_ctx13.ictrl_ctx0', [0])
xhci_70.add_flag('ictrl_ctx13.ictrl_ctx1', {0: 2, 2: '30@0'})
xhci_70.add_struct('XHCITRB0', {'parameter#0x8': FIELD_POINTER, 'status#0x4': FIELD_FLAG, 'control#0x4': FIELD_FLAG, 'addr#0x8': FIELD_RANDOM, 'ccs#0x1': FIELD_RANDOM})
xhci_70.add_flag('XHCITRB0.control', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 2, 9: 1, 10: 6, 16: 5, 21: 3, 24: 8})
xhci_70.add_flag('XHCITRB0.status', {0: 16, 16: 6, 22: 10})
xhci_70.add_point_to('XHCITRB0.parameter', [
    None, None, None, None, None, None, None, None, None, None, None, 'ictrl_ctx11', 'ictrl_ctx12', 'ictrl_ctx13', None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None], flags=['XHCITRB0.control.10'])
xhci_70.add_head(['XHCITRB0'])
xhci_70.add_instrumentation_point('hcd-xhci.c', ['xhci_ring_fetch', 'pci_dma_read', 0, 1])
xhci_70.add_instrumentation_point('hcd-xhci.c', ['xhci_ring_chain_length', 'pci_dma_read', 0, 1])
###################################################################################################################
xhci_71 = Model('xhci', 71)
xhci_71.add_struct('XHCITRB1', {'parameter#0x8': FIELD_POINTER, 'status#0x4': FIELD_FLAG, 'control#0x4': FIELD_FLAG, 'addr#0x8': FIELD_RANDOM, 'ccs#0x1': FIELD_RANDOM})
xhci_71.add_flag('XHCITRB1.control', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 2, 9: 1, 10: 6, 16: 5, 21: 3, 24: 8})
xhci_71.add_flag('XHCITRB1.status', {0: 16, 16: 6, 22: 10})
xhci_71.add_struct('XHCI_BUF0', {'buf#0x1000': FIELD_RANDOM})
xhci_71.add_point_to('XHCITRB1.parameter', ['XHCI_BUF0'])
xhci_71.add_struct('XHCIEvRingSeg', {'addr#0x8': FIELD_POINTER, 'size#0x4': FIELD_RANDOM, 'rsvd#0x4': FIELD_RANDOM})
xhci_71.add_point_to('XHCIEvRingSeg.addr', ['XHCITRB1'], array=True)
xhci_71.add_head(['XHCIEvRingSeg'])
xhci_71.add_instrumentation_point('hcd-xhci.c', ['xhci_er_reset', 'pci_dma_read', 0, 1])
###################################################################################################################
xhci_72 = Model('xhci', 72)
xhci_72.add_struct('XHCI_POCTX', {'poctx#0x8': FIELD_POINTER})
xhci_72.add_struct('XHCI_OCTX00', {'slot_ctx#0x10': FIELD_RANDOM})
xhci_72.add_point_to('XHCI_POCTX.poctx', ['XHCI_OCTX00'])
xhci_72.add_head(['XHCI_POCTX'])
xhci_72.add_instrumentation_point('hcd-xhci.c', ['xhci_address_slot', 'ldq_le_pci_dma', 0, 1])
###################################################################################################################
xhci_73 = Model('xhci', 73)
xhci_73.add_struct('XHCI_CTX0', {'ctx0#0x4': FIELD_FLAG, 'ctx1#0x4': FIELD_RANDOM})
xhci_73.add_flag('XHCI_CTX0.ctx0', {0: 1, 1: 3, 4: 28})
xhci_73.add_head(['XHCI_CTX0'])
xhci_73.add_instrumentation_point('hcd-xhci.c', ['xhci_find_stream', 'xhci_dma_read_u32s', 0, 1])
###################################################################################################################
xhci_74 = Model('xhci', 74)
xhci_74.add_struct('XHCI_CTX1', {'ctx#0x14': FIELD_RANDOM})
xhci_74.add_head(['XHCI_CTX1'])
xhci_74.add_instrumentation_point('hcd-xhci.c', ['xhci_set_ep_state', 'xhci_dma_read_u32s', 0, 1])
###################################################################################################################
xhci_75 = Model('xhci', 75)
xhci_75.add_struct('XHCI_CTX2', {'ctx#0x8': FIELD_RANDOM})
xhci_75.add_head(['XHCI_CTX2'])
xhci_75.add_instrumentation_point('hcd-xhci.c', ['xhci_set_ep_state', 'xhci_dma_read_u32s', 1, 1])
###################################################################################################################
xhci_76 = Model('xhci', 76)
xhci_76.add_struct('XHCI_SLOT_CTX', {
    'slot_ctx#0x20': FIELD_RANDOM,
    'ep_ctx0#0x20': FIELD_RANDOM, 'ep_ctx1#0x20': FIELD_RANDOM, 'ep_ctx2#0x20': FIELD_RANDOM, 'ep_ctx3#0x20': FIELD_RANDOM,
    'ep_ctx4#0x20': FIELD_RANDOM, 'ep_ctx5#0x20': FIELD_RANDOM, 'ep_ctx6#0x20': FIELD_RANDOM, 'ep_ctx7#0x20': FIELD_RANDOM,
    'ep_ctx8#0x20': FIELD_RANDOM, 'ep_ctx9#0x20': FIELD_RANDOM, 'ep_ctx10#0x20': FIELD_RANDOM, 'ep_ctx11#0x20': FIELD_RANDOM,
    'ep_ctx12#0x20': FIELD_RANDOM, 'ep_ctx13#0x20': FIELD_RANDOM, 'ep_ctx14#0x20': FIELD_RANDOM, 'ep_ctx15#0x20': FIELD_RANDOM,
    'ep_ctx16#0x20': FIELD_RANDOM, 'ep_ctx17#0x20': FIELD_RANDOM, 'ep_ctx18#0x20': FIELD_RANDOM, 'ep_ctx19#0x20': FIELD_RANDOM,
    'ep_ctx20#0x20': FIELD_RANDOM, 'ep_ctx21#0x20': FIELD_RANDOM, 'ep_ctx22#0x20': FIELD_RANDOM, 'ep_ctx23#0x20': FIELD_RANDOM,
    'ep_ctx24#0x20': FIELD_RANDOM, 'ep_ctx25#0x20': FIELD_RANDOM, 'ep_ctx26#0x20': FIELD_RANDOM, 'ep_ctx27#0x20': FIELD_RANDOM,
    'ep_ctx28#0x20': FIELD_RANDOM, 'ep_ctx29#0x20': FIELD_RANDOM, 'ep_ctx30#0x20': FIELD_RANDOM, 'ep_ctx31#0x20': FIELD_RANDOM})
xhci_76.add_head(['XHCI_SLOT_CTX'])
xhci_76.add_instrumentation_point('hcd-xhci.c', ['usb_xhci_post_load', 'xhci_dma_read_u32s', 0, 1])
###################################################################################################################
xhci_77 = Model('xhci', 77)
xhci_77.add_struct('XHCI_OCTX01', {'slot_ctx#0x10': FIELD_RANDOM})
xhci_77.add_head(['XHCI_OCTX01'])
xhci_77.add_instrumentation_point('hcd-xhci.c', ['xhci_configure_slot', 'xhci_dma_read_u32s', 0, 1])
xhci_77.add_instrumentation_point('hcd-xhci.c', ['xhci_configure_slot', 'xhci_dma_read_u32s', 2, 1])
xhci_77.add_instrumentation_point('hcd-xhci.c', ['xhci_reset_slot', 'xhci_dma_read_u32s', 0, 1])
###################################################################################################################
xhci_78 = Model('xhci', 78)
xhci_78.add_struct('XHCI_OCTX1', {'slot_ctx#0x20': FIELD_RANDOM, 'ep0_ctx#0x14': FIELD_RANDOM})
xhci_78.add_head(['XHCI_OCTX1'])
xhci_78.add_instrumentation_point('hcd-xhci.c', ['xhci_evaluate_slot', 'xhci_dma_read_u32s', 2, 1])
###################################################################################################################
uhci_79 = Model('uhci', 79)
uhci_79.add_struct('link', {'link#0x4': FIELD_POINTER | FIELD_FLAG})
uhci_79.add_flag('link.link', {0: '1@0', 1: 1})
uhci_79.add_struct('UHCI_BUF0', {'buf#0x1000': FIELD_RANDOM})
uhci_79.add_point_to('link.link', ['UHCI_BUF0'], alignment=4)
uhci_79.add_head(['link'])
uhci_79.add_instrumentation_point('hcd-uhci.c', ['uhci_process_frame', 'pci_dma_read', 0, 1])
###################################################################################################################
uhci_83 = Model('uhci', 83)
uhci_83.add_struct('UHCI_QH', {'link#0x4': FIELD_POINTER | FIELD_FLAG, 'el_link#0x4': FIELD_POINTER | FIELD_FLAG})
uhci_83.add_flag('UHCI_QH.el_link', {0: '1@0', 1: 1})
uhci_83.add_flag('UHCI_QH.link', {0: '1@0', 1: 1})
uhci_83.add_struct('UHCI_BUF1', {'buf#0x1000': FIELD_RANDOM})
uhci_83.add_struct('UHCI_BUF2', {'buf#0x1000': FIELD_RANDOM})
uhci_83.add_point_to('UHCI_QH.link', ['UHCI_BUF1'])
uhci_83.add_point_to('UHCI_QH.el_link', ['UHCI_BUF2'])
uhci_83.add_head(['UHCI_QH'])
uhci_83.add_instrumentation_point('hcd-uhci.c', ['uhci_process_frame', 'pci_dma_read', 1, 1])
###################################################################################################################
uhci_84 = Model('uhci', 84)
uhci_84.add_struct('UHCI_TD', {'link#0x4': FIELD_POINTER | FIELD_FLAG, 'ctrl#0x4': FIELD_FLAG, 'token#0x4': FIELD_FLAG, 'buffer#0x4': FIELD_POINTER})
uhci_84.add_flag('UHCI_TD.ctrl', {0: 18, 18: 1, 19: 1, 20: 1, 21: 1, 22: 1, 23: 1, 24: 1, 25: 1, 27: 2, 29: 1, 30: 2})
uhci_84.add_flag('UHCI_TD.token', {0: 8, 8: '7@0', 15: 4, 21: 11})
uhci_84.add_flag('UHCI_TD.link', {0: '1@0', 1: 1})
uhci_84.add_struct('UHCI_BUF3', {'buf#0x1000': FIELD_RANDOM})
uhci_84.add_struct('UHCI_BUF4', {'buf#0x1000': FIELD_RANDOM})
uhci_84.add_point_to('UHCI_TD.link', ['UHCI_BUF3'])
uhci_84.add_point_to('UHCI_TD.buffer', ['UHCI_BUF4'])
uhci_84.add_head(['UHCI_TD'])
uhci_84.add_instrumentation_point('hcd-uhci.c', ['uhci_read_td', 'pci_dma_read', 0, 1])
###################################################################################################################
ohci_80 = Model('ohci', 80)
ohci_80.add_struct('OHCI_BUF0', {'buf#0x1000': FIELD_RANDOM})
t = {}
for i in range(0, 32):
    t['intr{}#0x4'.format(i)] = FIELD_POINTER
t.update({'frame#0x2': FIELD_RANDOM, 'pad#0x2': FIELD_RANDOM, 'done#0x4': FIELD_RANDOM})
ohci_80.add_struct('OHCI_HCCA', t)
for i in range(0, 32):
    ohci_80.add_point_to('OHCI_HCCA.intr{}'.format(i), ['OHCI_BUF0'])
ohci_80.add_head(['OHCI_HCCA'])
ohci_80.add_instrumentation_point('hcd-ohci.c', ['ohci_read_hcca', 'dma_memory_read', 0, 1])
###################################################################################################################
ohci_81 = Model('ohci', 81)
ohci_81.add_struct('OHCI_BUF1', {'buf#0x1000': FIELD_RANDOM})
ohci_81.add_struct('OHCI_ED', {'flags#0x4': FIELD_FLAG, 'tail#0x4': FIELD_POINTER , 'head#0x4': FIELD_POINTER, 'next#0x4': FIELD_POINTER})
ohci_81.add_flag('OHCI_ED.flags', {0: '7@0x0', 7: 4, 11: 2, 13: 1, 14: 1, 15: 1, 16: 11, 27: 5})
ohci_81.add_point_to('OHCI_ED.next', ['OHCI_BUF1'], alignment=4)
ohci_81.add_struct('OHCI_TD', {'flags#0x4': FIELD_FLAG, 'cbp#0x4': FIELD_RANDOM, 'next#0x4': FIELD_POINTER, 'be#0x4': FIELD_RANDOM})
ohci_81.add_flag('OHCI_TD.flags', {0: 16, 18: 1, 19: 2, 21: 3, 24: 1, 25: 1, 26: 2, 28: 4})
ohci_81.add_point_to('OHCI_TD.next', ['OHCI_TD'], alignment=4)
ohci_81.add_struct('OHCI_ISO_TD', {
    'flags#0x4': FIELD_FLAG, 'bp#0x4': FIELD_RANDOM, 'next#0x4': FIELD_POINTER, 'be#0x4': FIELD_RANDOM,
    'offset0#0x2': FIELD_RANDOM, 'offset1#0x2': FIELD_RANDOM, 'offset2#0x2': FIELD_RANDOM, 'offset3#0x2': FIELD_RANDOM,
    'offset4#0x2': FIELD_RANDOM, 'offset5#0x2': FIELD_RANDOM, 'offset6#0x2': FIELD_RANDOM, 'offset7#0x2': FIELD_RANDOM})
ohci_81.add_flag('OHCI_ISO_TD.flags', {0: 16, 18: 1, 19: 2, 21: 3, 24: 1, 25: 1, 26: 2, 28: 4})
ohci_81.add_point_to('OHCI_ISO_TD.next', ['OHCI_ISO_TD'], alignment=4)
ohci_81.add_point_to_single_linked_list('OHCI_ED.head', 'OHCI_ED.tail', ['OHCI_TD', 'OHCI_ISO_TD'], ['next', 'next'], flags=['OHCI_ED.flags.15'], alignment=4)
ohci_81.add_head(['OHCI_ED'])
ohci_81.add_instrumentation_point('hcd-ohci.c', ['ohci_service_ed_list', 'ohci_read_ed', 0, 1])
###################################################################################################################
ehci_82 = Model('ehci', 82)
ehci_82.add_struct('list', {'list#0x4': FIELD_POINTER})
ehci_82.add_struct('list_buf', {'buf#0x1000': FIELD_RANDOM})
ehci_82.add_struct('entry', {'entry#0x4': FIELD_POINTER | FIELD_FLAG})
ehci_82.add_flag('entry.entry', {0: 1, 1: 2})
ehci_82.add_point_to('entry.entry', ['list_buf'])
ehci_82.add_point_to('list.list', ['entry'])
ehci_82.add_head(['list'])
ehci_82.add_instrumentation_point('hcd-ehci.c', ['ehci_advance_periodic_state', 'get_dwords', 0, 1])
###################################################################################################################
ehci_87 = Model('ehci', 87)
ehci_87.add_struct('EHCIqtd_BUF0', {'buf#0x1000': FIELD_RANDOM})
ehci_87.add_struct('EHCIqtd', {
    'next#0x4': FIELD_POINTER, 'altnext#0x4': FIELD_POINTER, 'token#0x4': FIELD_FLAG,
    'bufptr0#0x4': FIELD_POINTER, 'bufptr1#0x4': FIELD_POINTER, 'bufptr2#0x4': FIELD_POINTER,
    'bufptr3#0x4': FIELD_POINTER, 'bufptr4#0x4': FIELD_POINTER})
ehci_87.add_flag('EHCIqtd.token', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 2, 10: 2, 12: 3, 15: 1, 16: 15, 31: 1})
ehci_87.add_point_to('EHCIqtd.next', ['EHCIqtd_BUF0'])
ehci_87.add_point_to('EHCIqtd.altnext', ['EHCIqtd_BUF0'])
for i in range(0, 5):
    ehci_87.add_point_to('EHCIqtd.bufptr{}'.format(i), ['EHCIqtd_BUF0'])
ehci_87.add_head(['EHCIqtd'])
ehci_87.add_instrumentation_point('hcd-ehci.c', ['ehci_writeback_async_complete_packet', 'get_dwords', 1, 1])
ehci_87.add_instrumentation_point('hcd-ehci.c', ['ehci_state_fetchqtd', 'get_dwords', 0, 1])
ehci_87.add_instrumentation_point('hcd-ehci.c', ['ehci_fill_queue', 'get_dwords', 0, 1])
###################################################################################################################
ehci_88 = Model('ehci', 88)
ehci_88.add_struct('EHCIqh_BUF0', {'buf#0x1000': FIELD_RANDOM})
ehci_88.add_struct('EHCIqh', {
    'next#0x4': FIELD_POINTER, 'epchar#0x4': FIELD_FLAG, 'epcap#0x4': FIELD_FLAG,
    'current_qtd#0x4': FIELD_POINTER | FIELD_FLAG, 'next_qtd#0x4': FIELD_POINTER | FIELD_FLAG, 'altnext_qtd#0x4': FIELD_POINTER | FIELD_FLAG,
    'token#0x4': FIELD_FLAG,
    'bufptr0#0x4': FIELD_POINTER, 'bufptr1#0x4': FIELD_POINTER,
    'bufptr2#0x4': FIELD_POINTER, 'bufptr3#0x4': FIELD_POINTER, 'bufptr4#0x4': FIELD_POINTER})
ehci_88.add_flag('EHCIqh.epchar', {0: '7@0', 7: 1, 8: 4, 12: 2, 14: 1, 15: 1, 16: 11, 27: 1, 28: 4})
ehci_88.add_flag('EHCIqh.epcap', {0: 8, 8: 8, 16: 4, 23: 7, 30: 2})
ehci_88.add_flag('EHCIqh.token', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 2, 10: 2, 12: 3, 15: 1, 16: 15, 31: 1})
ehci_88.add_flag('EHCIqh.current_qtd', {0: 1})
ehci_88.add_flag('EHCIqh.next_qtd', {0: 1})
ehci_88.add_flag('EHCIqh.altnext_qtd', {0: 1})
ehci_88.add_point_to('EHCIqh.next', ['EHCIqh_BUF0'])
ehci_88.add_point_to('EHCIqh.current_qtd', ['EHCIqh_BUF0'])
ehci_88.add_point_to('EHCIqh.next_qtd', ['EHCIqh_BUF0'])
ehci_88.add_point_to('EHCIqh.altnext_qtd', ['EHCIqh_BUF0'])
for i in range(0, 5):
    ehci_88.add_point_to('EHCIqh.bufptr{}'.format(i), ['EHCIqh_BUF0'])
ehci_88.add_head(['EHCIqh'])
ehci_88.add_instrumentation_point('hcd-ehci.c', ['ehci_writeback_async_complete_packet', 'get_dwords', 0, 1])
ehci_88.add_instrumentation_point('hcd-ehci.c', ['ehci_state_waitlisthead', 'get_dwords', 0, 1])
ehci_88.add_instrumentation_point('hci-ehci.c', ['ehci_state_fetchqh', 'get_dwords', 0, 1])
###################################################################################################################
ehci_85 = Model('ehci', 85)
ehci_85.add_struct('EHCIitd_BUF0', {'buf#0x1000': FIELD_RANDOM})
ehci_85.add_struct('EHCIitd', {
    'next#0x4': FIELD_POINTER,
    'transact0#0x4': FIELD_FLAG, 'transact1#0x4': FIELD_FLAG, 'transact2#0x4': FIELD_FLAG,
    'transact3#0x4': FIELD_FLAG, 'transact4#0x4': FIELD_FLAG, 'transact5#0x4': FIELD_FLAG,
    'transact6#0x4': FIELD_FLAG, 'transact7#0x4': FIELD_FLAG,
    'bufptr0#0x4': FIELD_POINTER | FIELD_FLAG, 'bufptr1#0x4': FIELD_POINTER | FIELD_FLAG, 'bufptr2#0x4': FIELD_POINTER | FIELD_FLAG,
    'bufptr3#0x4': FIELD_POINTER, 'bufptr4#0x4': FIELD_POINTER, 'bufptr5#0x4': FIELD_POINTER, 'bufptr6#0x4': FIELD_POINTER})
for i in range(0, 8):
    ehci_85.add_flag('EHCIitd.transact{}'.format(i), {0: 12, 12: 3, 15: 1, 16: 12, 28: 1, 29: 1, 30: 1, 31: 1})
ehci_85.add_flag('EHCIitd.bufptr0', {0: '7@0', 8: 4})
ehci_85.add_flag('EHCIitd.bufptr1', {0: 11, 11: 1})
ehci_85.add_flag('EHCIitd.bufptr2', {0: 2})
for i in range(0, 7):
    ehci_85.add_point_to('EHCIitd.bufptr{}'.format(i), ['EHCIitd_BUF'])
ehci_85.add_point_to('EHCIitd.next', ['EHCIitd_BUF'])
ehci_85.add_head(['EHCIitd_BUF0'])
ehci_85.add_instrumentation_point('hcd-ehci.c', ['ehci_state_fetchitd', 'get_dwords', 0, 1])
###################################################################################################################
ehci_86 = Model('ehci', 86)
ehci_86.add_struct('EHCIsitd_BUF0', {'buf#0x1000': FIELD_RANDOM})
ehci_86.add_struct('EHCIsitd', {
    'next#0x4': FIELD_POINTER, 'epchar#0x4': FIELD_FLAG, 'uframe#0x4': FIELD_FLAG, 'results#0x4': FIELD_FLAG,
    'bufptr0#0x4': FIELD_RANDOM, 'bufptr1#0x4': FIELD_RANDOM, 'backptr#0x4': FIELD_RANDOM})
ehci_86.add_flag('EHCIsitd.epchar', {0: 7, 7: 1, 8: 4, 12: 4, 16: 7, 23: 1, 24: 7, 31: 1})
ehci_86.add_flag('EHCIsitd.uframe', {0: 8, 8: 8, 16: 16})
ehci_86.add_flag('EHCIsitd.results', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 8, 16: 11, 27: 3, 30: 1, 31: 1})
ehci_86.add_point_to('EHCIsitd.next', ['EHCIsitd_BUF0'])
ehci_86.add_head(['EHCIsitd'])
ehci_86.add_instrumentation_point('hcd-ehci.c', ['ehci_state_fetchsitd', 'get_dwords', 0, 1])
###################################################################################################################
