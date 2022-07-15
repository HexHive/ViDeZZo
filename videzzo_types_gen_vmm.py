from videzzo_types_lib import Model
from videzzo_types_lib import FIELD_RANDOM, FIELD_FLAG, FIELD_POINTER, FIELD_CONSTANT
from videzzo_types_lib import dict_append

# id slots
# - audio: 00-09
# - network: 10-39, 100-110
# - block: 40-69
# - usb: 70-99
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
# ac97_00.add_instrumentation_point('ac97.c', ['fetch_bd', 'pci_dma_read', 0, 1])
###################################################################################################################
cs4231a_01 = Model('cs4231a', 1)
cs4231a_01.add_struct('CS4231A_BUF0', {'buf#0x1000': FIELD_RANDOM})
cs4231a_01.add_head(['CS4231A_BUF0'])
# cs4231a_01.add_instrumentation_point('cs4231a.c', ['i8257_dma_read_memory', 'cpu_physical_memory_read', 0, 0])
###################################################################################################################
es1370_02 = Model('es1370', 2)
es1370_02.add_struct('ES1370_BUF0', {'buf#0x1000': FIELD_RANDOM})
es1370_02.add_head(['ES1370_BUF0'])
# es1370_02.add_instrumentation_point('es1370.c', ['es1370_transfer_audio', 'pci_dma_read', 0, 1])
###################################################################################################################
intel_hda_03 = Model('intel_hda', 3)
intel_hda_03.add_struct('INTEL_HDA_BUF0', {'addr#0x8': FIELD_POINTER, 'len#0x4': FIELD_CONSTANT, 'flags#0x4': FIELD_FLAG})
intel_hda_03.add_struct('INTEL_HDA_BUF1', {'buf#0x1000': FIELD_RANDOM})
intel_hda_03.add_point_to('INTEL_HDA_BUF0.addr', ['INTEL_HDA_BUF1'])
# 2.4.1.3 we have to enforce the lenght of INTEL_HDA_BUF1
intel_hda_03.add_constant('INTEL_HDA_BUF0.len', [0x1000])
intel_hda_03.add_flag('INTEL_HDA_BUF0.flags', {0: 1, 1: 31})
intel_hda_03.add_head(['INTEL_HDA_BUF0'])
# intel_hda_03.add_instrumentation_point('intel-hda.c', ['intel_hda_parse_bdl', 'pci_dma_read', 0, 1])
###################################################################################################################
intel_hda_04 = Model('intel_hda', 4)
intel_hda_04.add_struct('INTEL_HDA_VERB', {'verb#0x4': FIELD_FLAG})
intel_hda_04.add_flag('INTEL_HDA_VERB.verb', {0: 8, 8: 12, 20: 7, 27: 1, 28: 4})
intel_hda_04.add_head(['INTEL_HDA_VERB'])
# intel_hda_04.add_instrumentation_point('intel-hda.c', ['intel_hda_corb_run', 'ldl_le_pci_dma', 0, 1])
###################################################################################################################
sb16_05 = Model('sb16', 5)
sb16_05.add_struct('SB16_BUF0', {'buf#0x1000': FIELD_RANDOM})
sb16_05.add_head(['SB16_BUF0'])
# sb16_05.add_instrumentation_point('i8257.c', ['i8257_dma_read_memory', 'cpu_physical_memory_read', 0, 0])
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
# eepro100_11.add_instrumentation_point('eepro100.c', ['set_multicast_list', 'pci_dma_read', 0, 1])
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
# eepro100_10.add_instrumentation_point('eepro100.c', ['read_cb', 'pci_dma_read', 0, 1])
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
# eepro100_12.add_instrumentation_point('eepro100.c', ['nic_receive', 'pci_read_dma', 0, 1])
###################################################################################################################
e1000_tx_desc = {'buffer_addr#0x8': FIELD_POINTER,
                 'flags#0x4': FIELD_FLAG, 'fields#0x4': FIELD_FLAG}
e1000_context_desc = {'ip_fields#0x4': FIELD_FLAG, 'tcp_fields#0x4': FIELD_FLAG,
                      'cmd_and_length#0x4': FIELD_FLAG, 'fields#0x4': FIELD_FLAG}
###################################################################################################################
e1000e_13 = Model('e1000e', 13) # 15 is available
e1000e_13.add_struct('E1000_TX_DESC0', e1000_tx_desc)
e1000e_13.add_flag('E1000_TX_DESC0.flags', {0: 16, 16: 4, 20: 1, 21: 7, 28: 1, 29: 1, 30: 2})
e1000e_13.add_flag('E1000_TX_DESC0.fields', {0: 4, 4: 1, 5: 11, 16: 8, 24: 8})
e1000e_13.add_struct('E1000E_BUF0', {'buf#0x10000': FIELD_RANDOM})
e1000e_13.add_point_to('E1000_TX_DESC0.buffer_addr', ['E1000E_BUF0'])
e1000e_13.add_struct('E1000_CONTEXT_DESC', e1000_context_desc)
e1000e_13.add_flag('E1000_CONTEXT_DESC.ip_fields', {0: 8, 8: 8, 16: 16})
e1000e_13.add_flag('E1000_CONTEXT_DESC.tcp_fields', {0: 8, 8: 8, 16: 16})
e1000e_13.add_flag('E1000_CONTEXT_DESC.fields', {0: 8, 8: 8, 16: 16})
e1000e_13.add_flag('E1000_CONTEXT_DESC.cmd_and_length', {0: 16, 16: 4, 20: 1, 21: 3, 24: 1, 25: 1, 26: 1, 27: 2, 29: 1, 30: 1, 31: 1})
e1000e_13.add_head(['E1000_TX_DESC0', 'E1000_CONTEXT_DESC'])
# 3.2.1 we use a round-robin approach to support e1000_tx_desc and e1000_context_desc
# e1000e_13.add_instrumentation_point('e1000e_core.c', ['e1000e_start_xmit', 'pci_dma_read', 0, 1])
# e1000e_13.add_instrumentation_point('e1000.c', ['start_xmit', 'pci_dma_read', 0, 1])
###################################################################################################################
e1000e_14 = Model('e1000e', 14)
# 3.2.2 e1000e_read_rx_descr, e1000_rx_desc_packet_split, e1000_rx_desc_extended share buffer_addr and other staff
# However, it seems we don't use any other fields except buffer_addr, so make other staff random.
e1000e_14.add_struct('E1000E_READ_RX_DESC', {'buffer_addr0#0x8': FIELD_POINTER, 'buffer_addr1#0x8': FIELD_RANDOM,
                              'buffer_addr2#0x8': FIELD_RANDOM, 'buffer_addr3#0x8': FIELD_RANDOM})
e1000e_14.add_struct('E1000E_BUF1', {'buf#0x1000': FIELD_RANDOM})
e1000e_14.add_point_to('E1000E_READ_RX_DESC.buffer_addr0', ['E1000E_BUF1'])
e1000e_14.add_head(['E1000E_READ_RX_DESC'])
# e1000e_14.add_instrumentation_point('e1000e_core.c', ['e1000e_write_packet_to_guest', 'pci_dma_read', 0, 1])
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
# e1000_16.add_instrumentation_point('e1000.c', ['e1000_receive_iov', 'pci_dma_read', 0, 1])
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
# pcnet_17.add_instrumentation_point('pcnet.c', ['pcnet_tmd_load', 'phys_mem_read', 0, 1])
###################################################################################################################
pcnet_18 = Model('pcnet', 18)
pcnet_18.add_struct('PCNET_TMD', {'tbadr#0x4': FIELD_POINTER, 'length#0x2': FIELD_RANDOM, 'status#0x2': FIELD_FLAG, 'misc#0x4': FIELD_FLAG, 'res#0x4': FIELD_RANDOM})
pcnet_18.add_flag('PCNET_TMD.status', {0: 7, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 15: 1, 16: 16})
pcnet_18.add_flag('PCNET_TMD.misc', {0: 4, 4: 12, 16: 10, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
pcnet_18.add_struct('PCNET_BUF1', {'buf#0x1000': FIELD_RANDOM})
pcnet_18.add_point_to('PCNET_TMD.tbadr', ['PCNET_BUF1'])
# 3.3.1 we handle pointer|flag union as a flag: pcnet_tmd_load from 321 to 325 swaps misc and tbadr
pcnet_18.add_head(['PCNET_TMD'])
# pcnet_18.add_instrumentation_point('pcnet.c', ['pcnet_tmd_load', 'phys_mem_read', 1, 1])
###################################################################################################################
pcnet_19 = Model('pcnet', 19)
pcnet_19.add_struct('PCNET_RDA', {'rbadr#0x4': FIELD_POINTER | FIELD_FLAG, 'buf_length#0x2': FIELD_RANDOM, 'msg_length#0x2': FIELD_FLAG})
pcnet_19.add_flag('PCNET_RDA.rbadr', {24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
pcnet_19.add_flag('PCNET_RDA.msg_length', {0: 12, 12: 4})
pcnet_19.add_struct('PCNET_BUF2', {'buf#0x1000': FIELD_RANDOM})
pcnet_19.add_point_to('PCNET_RDA.rbadr', ['PCNET_BUF2'])
pcnet_19.add_head(['PCNET_RDA'])
# pcnet_19.add_instrumentation_point('pcnet.c', ['pcnet_rmd_load', 'phys_mem_read', 0, 1])
###################################################################################################################
pcnet_20 = Model('pcnet', 20)
pcnet_20.add_struct('PCNET_RMD', {'rbadr#0x4': FIELD_POINTER, 'buf_length#0x2': FIELD_RANDOM, 'status#0x2': FIELD_FLAG, 'msg_length#0x4': FIELD_FLAG, 'res#0x4': FIELD_RANDOM})
pcnet_20.add_flag('PCNET_RMD.status', {0: 4, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 15: 1, 16: 16})
pcnet_20.add_flag('PCNET_RMD.msg_length', {0: 12, 12: 4, 16: 8, 24: 8})
pcnet_20.add_struct('PCNET_BUF3', {'buf#0x1000': FIELD_RANDOM})
pcnet_20.add_point_to('PCNET_RMD.rbadr', ['PCNET_BUF3'])
# 3.3.1 we handle pointer|flag union as a flag: pcnet_tmd_load from 390 to 394 swaps misc and tbadr
pcnet_20.add_head(['PCNET_RMD'])
# pcnet_20.add_instrumentation_point('pcnet.c', ['pcnet_rmd_load', 'phys_mem_read', 1, 1])
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
pcnet_21.add_instrumentation_point('DevPCNet.cpp', ['_ZL11pcnetR3InitP11PDMDEVINSR3P10PCNETSTATEP12PCNETSTATER3', '_ZL13pcnetPhysReadP11PDMDEVINSR3P10PCNETSTATEmPvm', 0, 2])
###################################################################################################################
pcnet_22 = Model('pcnet', 22)
pcnet_22.add_struct('PCNET_INITBLK16', {
    'mode#0x2': FIELD_FLAG, 'padrf0#0x2': FIELD_RANDOM, 'padrf1#0x2': FIELD_RANDOM, 'padrf2#0x2': FIELD_RANDOM,
    'ladrf0#0x2': FIELD_RANDOM, 'ladrf1#0x2': FIELD_RANDOM, 'ladrf2#0x2': FIELD_RANDOM, 'ladrf3#0x2': FIELD_RANDOM,
    'rdra#0x4': FIELD_FLAG, 'tdra#0x4': FIELD_FLAG})
pcnet_22.add_flag('PCNET_INITBLK16.mode', {0: 1, 1: 1, 2: 1, 3: 1, 4: 2, 6: 1, 7: 6, 13: 1, 14: 1, 15: 1})
# 4.1.1 we replace 29, 3 with 24, 5, 3 (rdra and tdra).
pcnet_22.add_flag('PCNET_INITBLK16.rdra', {0: 24, 24: 5, 29: 3})
pcnet_22.add_flag('PCNET_INITBLK16.tdra', {0: 24, 24: 5, 29: 3})
# 4.1.2 we keep the existing more precise results
pcnet_22.add_flag('PCNET_INITBLK16.padrf0', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.padrf1', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.padrf2', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.ladrf0', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.ladrf1', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.ladrf2', {0: 8, 8: 8})
pcnet_22.add_flag('PCNET_INITBLK16.ladrf3', {0: 8, 8: 8})
pcnet_22.add_head(['PCNET_INITBLK16'])
pcnet_22.add_instrumentation_point('pcnet.c', ['pcnet_init', 'phys_mem_read', 1, 1])
pcnet_21.add_instrumentation_point('DevPCNet.cpp', ['_ZL11pcnetR3InitP11PDMDEVINSR3P10PCNETSTATEP12PCNETSTATER3', '_ZL13pcnetPhysReadP11PDMDEVINSR3P10PCNETSTATEmPvm', 1, 2])
###################################################################################################################
pcnet_23 = Model('pcnet', 23)
pcnet_23.add_struct('PCNET_BUF4', {'buf#0x1000': FIELD_RANDOM})
pcnet_23.add_head(['PCNET_BUF4'])
# pcnet_23.add_instrumentation_point('pcnet.c', ['pcnet_transmit', 'phys_mem_read', 0, 1])
###################################################################################################################
rtl8139_24 = Model('rtl8139', 24)
rtl8139_24.add_struct('RTL8139_RX_RING_DESC_RXDW0', {'rxdw0#0x4': FIELD_FLAG})
rtl8139_24.add_flag('RTL8139_RX_RING_DESC_RXDW0.rxdw0', {0: 13, 13: 1, 14: 1, 15: 1, 16: 1, 17: 1, 18: 1, 19: 1, 20: 4, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
rtl8139_24.add_head(['RTL8139_RX_RING_DESC_RXDW0'])
# rtl8139_24.add_instrumentation_point('rtl8139.c', ['rtl8139_do_receive', 'pci_dma_read', 0, 1])
###################################################################################################################
rtl8139_100 = Model('rtl8139', 100)
rtl8139_100.add_struct('RTL8139_RX_RING_DESC_RXDW1', {'rxdw1#0x4': FIELD_FLAG})
rtl8139_100.add_flag('RTL8139_RX_RING_DESC_RXDW1.rxdw1', {0: 13, 13: 1, 14: 1, 15: 1, 16: 1, 17: 1, 18: 1, 19: 1, 20: 4, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
rtl8139_100.add_head(['RTL8139_RX_RING_DESC_RXDW1'])
# rtl8139_100.add_instrumentation_point('rtl8139.c', ['rtl8139_do_receive', 'pci_dma_read', 1, 1])
###################################################################################################################
rtl8139_101 = Model('rtl8139', 101)
rtl8139_101.add_struct('RTL8139_RX_RING_DESC_BUF', {'buf#0x1000': FIELD_RANDOM})
rtl8139_101.add_struct('RTL8139_RX_RING_DESC_RXBUFLO', {'rxbuflo#0x4': FIELD_POINTER})
rtl8139_101.add_point_to('RTL8139_RX_RING_DESC_RXBUFLO.rxbuflo', ['RTL8139_RX_RING_DESC_BUF'])
rtl8139_101.add_head(['RTL8139_RX_RING_DESC_RXBUFLO'])
# rtl8139_101.add_instrumentation_point('rtl8139.c', ['rtl8139_do_receive', 'pci_dma_read', 2, 1])
###################################################################################################################
rtl8139_102 = Model('rtl8139', 102)
rtl8139_102.add_struct('RTL8139_RX_RING_DESC_RXBUFHI', {'rxbufhi#0x4': FIELD_CONSTANT})
rtl8139_102.add_constant('RTL8139_RX_RING_DESC_RXBUFHI.rxbufhi', [0])
rtl8139_102.add_head(['RTL8139_RX_RING_DESC_RXBUFHI'])
# rtl8139_102.add_instrumentation_point('rtl8139.c', ['rtl8139_do_receive', 'pci_dma_read', 3, 1])
###################################################################################################################
rtl8139_25 = Model('rtl8139', 25)
rtl8139_25.add_struct('RTL8139_BUF', {'buf#0x2000': FIELD_RANDOM})
rtl8139_25.add_head(['RTL8139_BUF'])
# rtl8139_25.add_instrumentation_point('rtl8139.c', ['rtl8139_transmit_one', 'pci_dma_read', 0, 1])
###################################################################################################################
rtl8139_26 = Model('rtl8139', 26)
rtl8139_26.add_struct('RTL8139_TX_RING_DESC_TXDW0', {'txdw0#0x4': FIELD_FLAG})
rtl8139_26.add_flag('RTL8139_TX_RING_DESC_TXDW0.txdw0', {0: 16, 16: 1, 17: 1, 18: 9, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
rtl8139_26.add_head(['RTL8139_TX_RING_DESC_TXDW0'])
# rtl8139_26.add_instrumentation_point('rtl8139.c', ['rtl8139_cplus_transmit_one', 'pci_dma_read', 0, 1])
###################################################################################################################
rtl8139_103 = Model('rtl8139', 103)
rtl8139_103.add_struct('RTL8139_TX_RING_DESC_TXDW1', {'txdw1#0x4': FIELD_FLAG})
rtl8139_103.add_flag('RTL8139_TX_RING_DESC_TXDW1.txdw1', {0: 16, 16: 1, 17: 1, 18: 14})
rtl8139_103.add_head(['RTL8139_TX_RING_DESC_TXDW1'])
# rtl8139_103.add_instrumentation_point('rtl8139.c', ['rtl8139_cplus_transmit_one', 'pci_dma_read', 1, 1])
###################################################################################################################
rtl8139_104 = Model('rtl8139', 104)
rtl8139_104.add_struct('RTL8139_TX_RING_DESC_BUF', {'buf#0x1000': FIELD_RANDOM})
rtl8139_104.add_struct('RTL8139_TX_RING_DESC_TXBUFLO', {'txbuflo#0x4': FIELD_POINTER})
rtl8139_104.add_point_to('RTL8139_TX_RING_DESC_TXBUFLO.txbuflo', ['RTL8139_TX_RING_DESC_BUF'])
rtl8139_104.add_head(['RTL8139_TX_RING_DESC_TXBUFLO'])
# rtl8139_104.add_instrumentation_point('rtl8139.c', ['rtl8139_cplus_transmit_one', 'pci_dma_read', 2, 1])
###################################################################################################################
rtl8139_105 = Model('rtl8139', 105)
rtl8139_105.add_struct('RTL8139_TX_RING_DESC_TXBUFHI', {'txbufhi#0x4': FIELD_CONSTANT})
rtl8139_105.add_constant('RTL8139_TX_RING_DESC_TXBUFHI.txbufhi', [0])
rtl8139_105.add_head(['RTL8139_TX_RING_DESC_TXBUFHI'])
# rtl8139_105.add_instrumentation_point('rtl8139.c', ['rtl8139_cplus_transmit_one', 'pci_dma_read', 3, 1])
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
# vmxnet3_27.add_instrumentation_point('vmxnet3.c', ['vmxnet3_activate_device', 'vmxnet3_verify_driver_magic', 0, 1])
###################################################################################################################
# floppy also uses i8257_dma_read_memory but we only instrument once
floppy_40 = Model('floppy', 40)
floppy_40.add_struct('FLOPPY_BUF', {'buf#0x1000': FIELD_RANDOM})
floppy_40.add_head(['FLOPPY_BUF'])
# floppy_40.add_instrumentation_point('i8257.c', ['i8257_dma_read_memory', 'cpu_physical_memory_read', 0, 0])
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
# ahci_42.add_instrumentation_point('ahci.c', ['handle_cmd', 'dma_memory_map', 0, 1])
###################################################################################################################
ahci_43 = Model('ahci', 43)
ahci_43.add_struct('AHCI_SG', {'addr#0x8': FIELD_POINTER, 'reserved#0x4': FIELD_RANDOM, 'flags_size#0x4': FIELD_RANDOM})
ahci_43.add_struct('AHCI_BUF', {'buf#0x1000': FIELD_RANDOM})
ahci_43.add_point_to('AHCI_SG.addr', ['AHCI_BUF'])
ahci_43.add_head(['AHCI_SG'])
# ahci_42.add_instrumentation_point('ahci.c', ['ahci_populate_sglist', 'dma_memory_map', 0, 1])
###################################################################################################################
ahci_44 = Model('ahci', 44)
ahci_44.add_struct('AHCI_RESFIS', {'resfix#0x1000': FIELD_RANDOM})
ahci_44.add_head(['AHCI_RESFIS'])
# ahci_44.add_instrumentation_point('ahci', ['ahci_map_fis_address', 'map_page', 0, 2])
###################################################################################################################
# This should be connected to 42, but I simplify it.
ahci_45 = Model('ahci', 45)
ahci_45.add_struct('AHCI_LST', {'lst#0x1000': FIELD_RANDOM})
ahci_45.add_head(['AHCI_LST'])
# ahci_45.add_instrumentation_point('ahci', ['ahci_map_fis_address', 'map_page', 0, 2])
###################################################################################################################
sdhci_46 = Model('sdhci', 46)
sdhci_46.add_struct('SDHCI_FIFO_BUFFER0', {'buf#0x1000': FIELD_RANDOM})
sdhci_46.add_head(['SDHCI_FIFO_BUFFER0'])
# sdhci_46.add_instrumentation_point('sdhci.c', ['sdhci_sdma_transfer_multi_blocks', 'dma_memory_read', 0, 1])
###################################################################################################################
sdhci_47 = Model('sdhci', 47)
sdhci_47.add_struct('SDHCI_FIFO_BUFFER1', {'buf#0x1000': FIELD_RANDOM})
sdhci_47.add_head(['SDHCI_FIFO_BUFFER1'])
# sdhci_47.add_instrumentation_point('sdhci.c', ['sdhci_sdma_transfer_single_block', 'dma_memory_read', 0, 1])
###################################################################################################################
sdhci_48 = Model('sdhci', 48)
sdhci_48.add_struct('SDHCI_ADMA2', {'attr#1': FIELD_RANDOM, 'reserved#1': FIELD_RANDOM, 'length#0x2': FIELD_RANDOM, 'addr#0x4': FIELD_POINTER})
sdhci_48.add_struct('SDHCI_ADMA2_BUF', {'buf#0x1000': FIELD_RANDOM})
sdhci_48.add_point_to('SDHCI_ADMA2.addr', ['SDHCI_ADMA2_BUF'])
sdhci_48.add_head(['SDHCI_ADMA2'])
# sdhci_48.add_instrumentation_point('sdhci.c', ['get_adma_description', 'dma_memory_read', 0, 1])
###################################################################################################################
sdhci_49 = Model('sdhci', 49)
sdhci_49.add_struct('SDHCI_ADMA1', {'adma1#0x4': FIELD_POINTER | FIELD_FLAG})
sdhci_49.add_flag('SDHCI_ADMA1.adma1', {0: 7})
sdhci_49.add_struct('SDHCI_ADMA1_BUF', {'buf#0x1000': FIELD_RANDOM})
sdhci_49.add_point_to('SDHCI_ADMA1.adma1', ['SDHCI_ADMA1_BUF'], alignment=7)
sdhci_49.add_head(['SDHCI_ADMA1'])
# sdhci_49.add_instrumentation_point('sdhci.c', ['get_adma_description', 'dma_memory_read', 1, 1])
###################################################################################################################
sdhci_50 = Model('sdhci', 50)
sdhci_50.add_struct('SDHCI_ADMA2_64', {'attr#1': FIELD_RANDOM, 'reserved#1': FIELD_RANDOM, 'length#0x2': FIELD_RANDOM, 'addr#0x8': FIELD_POINTER})
sdhci_50.add_struct('SDHCI_ADMA2_64_BUF', {'buf#0x1000': FIELD_RANDOM})
sdhci_50.add_point_to('SDHCI_ADMA2_64.addr', ['SDHCI_ADMA2_64_BUF'])
sdhci_50.add_head(['SDHCI_ADMA2_64'])
# sdhci_50.add_instrumentation_point('sdhci.c', ['get_adma_description', 'dma_memory_read', 2, 1])
###################################################################################################################
lsi53c895a_51 = Model('lsi53c895a', 51)
lsi53c895a_51.add_struct('LSI53C895A_BUF0', {'buf#0x1000': FIELD_RANDOM})
lsi53c895a_51.add_head(['LSI53C895A_BUF0'])
# lsi53c895a_51.add_instrumentation_point('lsi53c895a.c', ['lsi_mem_read', 'address_space_read', 0, 1])
# lsi53c895a_51.add_instrumentation_point('lsi53c895a.c', ['lsi_mem_read', 'pci_dma_read', 0, 1])
###################################################################################################################
lsi53c895a_52 = Model('lsi53c895a', 52)
lsi53c895a_52.add_struct('LSI53C895A_BUF1', {'sfbr#0x1': FIELD_RANDOM, 'pad_4#0x1': FIELD_RANDOM, 'reserved_6#0x8': FIELD_RANDOM})
lsi53c895a_52.add_head(['LSI53C895A_BUF1'])
# lsi53c895a_52.add_instrumentation_point('lsi53c895a.c', ['lsi_do_command', 'pci_dma_read', 0, 1])
###################################################################################################################
lsi53c895a_53 = Model('lsi53c895a', 53)
lsi53c895a_53.add_struct('LSI53C895A_BUF2', {'sfbr#0x1': FIELD_RANDOM})
lsi53c895a_53.add_head(['LSI53C895A_BUF2'])
# lsi53c895a_53.add_instrumentation_point('lsi53c895a.c', ['lsi_get_msgbyte', 'pci_dma_read', 0, 1])
###################################################################################################################
lsi53c895a_54 = Model('lsi53c895a', 54)
lsi53c895a_54.add_struct('LSI53C895A_BUF3', {'dbc#0x4': FIELD_FLAG, 'addr#0x4': FIELD_RANDOM})
lsi53c895a_54.add_flag('LSI53C895A_BUF3.dbc', {0: 8, 8: 2, 10: 6, 16: 8, 24: 8})
lsi53c895a_54.add_head(['LSI53C895A_BUF3'])
# lsi53c895a_54.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'pci_dma_read', 0, 1])
###################################################################################################################
lsi53c895a_55 = Model('lsi53c895a', 55)
lsi53c895a_55.add_struct('LSI53C895A_INST', {'inst#0x4': FIELD_FLAG})
# different instructions have differnet formats!!!!
lsi53c895a_55.add_flag('LSI53C895A_INST.inst', {0: 2, 2: 1, 3: 1, 4: 2, 6: 1, 7: 2, 9: 1, 10: 6, 16: 8, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 2})
lsi53c895a_55.add_head(['LSI53C895A_INST'])
# lsi53c895a_55.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 0, 1])
###################################################################################################################
lsi53c895a_56 = Model('lsi53c895a', 56)
lsi53c895a_56.add_struct('LSI53C895A_BUF4', {'buf#0x1000': FIELD_RANDOM})
lsi53c895a_56.add_struct('LSI53C895A_BUF5', {'addr#0x4': FIELD_POINTER})
lsi53c895a_56.add_point_to('LSI53C895A_BUF5.addr', ['LSI53C895A_BUF4'])
lsi53c895a_56.add_head(['LSI53C895A_BUF5'])
# lsi53c895a_56.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 1, 1])
# lsi53c895a_56.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 2, 1])
# lsi53c895a_56.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 3, 1])
# lsi53c895a_56.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 5, 1])
###################################################################################################################
lsi53c895a_57 = Model('lsi53c895a', 57)
lsi53c895a_57.add_struct('LSI53C895A_ID', {'id#0x4': FIELD_FLAG})
lsi53c895a_57.add_flag('LSI53C895A_ID.id', {0: 2, 2: 1, 3: 1, 4: 2, 6: 1, 7: 2, 9: 1, 10: 6, 16: 4, 20: 4, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 2})
lsi53c895a_57.add_head(['LSI53C895A_ID'])
# lsi53c895a_57.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'read_dword', 4, 1])
###################################################################################################################
lsi53c895a_58 = Model('lsi53c895a', 58)
lsi53c895a_58.add_struct('LSI53C895A_DATA', {'data#0x8': FIELD_RANDOM})
lsi53c895a_58.add_head(['LSI53C895A_DATA'])
# lsi53c895a_58.add_instrumentation_point('lsi53c895a.c', ['lsi_execute_script', 'pci_dma_read', 1, 1])
###################################################################################################################
megasas_59 = Model('megasas', 59)
megasas_59.add_struct('MEGASAS_REPLY_QUEUE_TAIL', {'reply_qeueu_tail#0x2': FIELD_RANDOM})
megasas_59.add_head(['MEGASAS_REPLY_QUEUE_TAIL'])
# megasas_59.add_instrumentation_point('megasas.c', ['megasas_enqueue_frame', 'ldl_le_pci_dma', 0, 1])
# megasas_59.add_instrumentation_point('megasas.c', ['megasas_complete_frame', 'ldl_le_pci_dma', 0, 1])
# megasas_59.add_instrumentation_point('megasas.c', ['megasas_complete_frame', 'ldl_le_pci_dma', 1, 1])
###################################################################################################################
# 3.2.1 we handle this struct-fusion in a smart way
megasas_60 = Model('megasas', 60)
# common header
__mfi_frame_header = {
    'frame_cmd#0x1': FIELD_CONSTANT, 'sense_len#0x1': FIELD_RANDOM, 'cmd_status#0x1': FIELD_RANDOM, 'scsi_status#0x1': FIELD_RANDOM,
    'target_id#0x1': FIELD_RANDOM, 'lun_id#0x1': FIELD_RANDOM, 'cdb_len#0x1': FIELD_RANDOM, 'sge_count#0x1': FIELD_RANDOM,
    'context#0x8': FIELD_RANDOM, 'flags0#0x2': FIELD_FLAG, 'timeout#0x2': FIELD_RANDOM, 'data_len#0x4': FIELD_RANDOM}
# 3.3.1 we cannot perfectly analyze union mfi_sgl so we use a under-approximation
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
# megasas_60.add_instrumentation_point('megasas.c', ['megasas_handle_frame', 'megasas_frame_get_context', 0, 1])
###################################################################################################################
xhci_70 = Model('xhci', 70)
xhci_70.add_struct('XHCI_BUF2', {'buf#0x1000': FIELD_RANDOM})
xhci_70.add_struct('XHCITRB0', {
    'parameter#0x8': FIELD_POINTER, 'status#0x4': FIELD_FLAG, 'control#0x4': FIELD_FLAG, 'addr#0x8': FIELD_RANDOM, 'ccs#0x1': FIELD_RANDOM})
xhci_70.add_flag('XHCITRB0.control', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 2, 9: 1, 10: 6, 16: 5, 21: 3, 24: 6, 30: '2@0'})
xhci_70.add_flag('XHCITRB0.status', {0: 16, 16: 6, 22: 10})
xhci_70.add_point_to('XHCITRB0.parameter', ['XHCI_BUF2'])
xhci_70.add_head(['XHCITRB0'])
# xhci_70.add_instrumentation_point('hcd-xhci.c', ['xhci_ring_fetch', 'dma_memory_read', 0, 1])
# xhci_70.add_instrumentation_point('hcd-xhci.c', ['xhci_ring_chain_length', 'dma_memory_read', 0, 1])
###################################################################################################################
xhci_71 = Model('xhci', 71)
xhci_71.add_struct('XHCITRB1', {
    'parameter#0x8': FIELD_POINTER, 'status#0x4': FIELD_FLAG, 'control#0x4': FIELD_FLAG, 'addr#0x8': FIELD_RANDOM, 'ccs#0x1': FIELD_RANDOM})
xhci_71.add_flag('XHCITRB1.control', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 2, 9: 1, 10: 6, 16: 5, 21: 3, 24: 6, 30: '2@0'})
xhci_71.add_flag('XHCITRB1.status', {0: 16, 16: 6, 22: 10})
xhci_71.add_struct('XHCI_BUF0', {'buf#0x1000': FIELD_RANDOM})
xhci_71.add_point_to('XHCITRB1.parameter', ['XHCI_BUF0'])
xhci_71.add_struct('XHCIEvRingSeg', {'addr#0x8': FIELD_POINTER, 'size#0x4': FIELD_FLAG, 'rsvd#0x4': FIELD_RANDOM})
xhci_71.add_flag('XHCIEvRingSeg.size', {0: 4, 4: 8, 12: '20@0'})
xhci_71.add_point_to('XHCIEvRingSeg.addr', ['XHCITRB1'])
xhci_71.add_head(['XHCIEvRingSeg'])
# xhci_71.add_instrumentation_point('hcd-xhci.c', ['xhci_er_reset', 'dma_memory_read', 0, 1])
###################################################################################################################
xhci_72 = Model('xhci', 72)
xhci_72.add_struct('XHCI_POCTX', {'poctx#0x8': FIELD_POINTER})
xhci_72.add_struct('XHCI_BUF1', {'buf#0x1000': FIELD_RANDOM})
xhci_72.add_point_to('XHCI_POCTX.poctx', ['XHCI_BUF1'])
xhci_72.add_head(['XHCI_POCTX'])
# xhci_72.add_instrumentation_point('hcd-xhci.c', ['xhci_address_slot', 'ldq_le_dma', 0, 1])
# xhci_72.add_instrumentation_point('hcd-xhci.c', ['usb_xhci_post_load', 'ldq_le_dma', 0, 1])
###################################################################################################################
xhci_73 = Model('xhci', 73) # 75 are available
xhci_73.add_struct('XHCI_CTX', {'ctx0#0x4': FIELD_FLAG, 'ctx1#0x4': FIELD_RANDOM})
xhci_73.add_flag('XHCI_CTX.ctx0', {0: 1, 1: 3, 4: 28})
xhci_73.add_head(['XHCI_CTX'])
# xhci_73.add_instrumentation_point('hcd-xhci.c', ['xhci_find_stream', 'xhci_dma_read_u32s', 0, 1])
# xhci_73.add_instrumentation_point('hcd-xhci.c', ['xhci_set_ep_state', 'xhci_dma_read_u32s', 0, 1])
# xhci_73.add_instrumentation_point('hcd-xhci.c', ['xhci_set_ep_state', 'xhci_dma_read_u32s', 1, 1])
###################################################################################################################
xhci_93 = Model('xhci', 93)
xhci_93.add_struct('XHCI_CTL_CTX', {'ctl_ctx0#0x4': FIELD_CONSTANT, 'ctl_ctx1#0x4': FIELD_CONSTANT})
xhci_93.add_constant('XHCI_CTL_CTX.ctl_ctx0', [0])
xhci_93.add_constant('XHCI_CTL_CTX.ctl_ctx1', [0, 1, 2, 3])
xhci_93.add_head(['XHCI_CTL_CTX'])
# xhci_93.add_instrumentation_point('hcd-xhci.c', ['xhci_evaluate_slot', 'xhci_dma_read_u32s', 0, 1])
# xhci_93.add_instrumentation_point('hcd-xhci.c', ['xhci_address_slot', 'xhci_dma_read_u32s', 0, 1])
###################################################################################################################
xhci_76 = Model('xhci', 76)
xhci_76.add_struct('XHCI_CTL_CTX_76', {'ctl_ctx0#0x4': FIELD_FLAG, 'ctl_ctx1#0x4': FIELD_FLAG})
xhci_76.add_flag('XHCI_CTL_CTX_76.ctl_ctx0', {
    0: '2@0', 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 15: 1,
    16: 1, 17: 1, 18: 1, 19: 1, 20: 1, 21: 1, 22: 1, 23: 1, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
xhci_76.add_flag('XHCI_CTL_CTX_76.ctl_ctx1', {0: '2@1', 2: 30})
xhci_76.add_head(['XHCI_CTL_CTX_76'])
# xhci_76.add_instrumentation_point('hcd-xhci.c', ['xhci_configure_slot', 'xhci_dma_read_u32s', 1, 1])
###################################################################################################################
xhci_94 = Model('xhci', 94) # 77 is available
xhci_94.add_struct('XHCI_SLOT_CTX', {'slot_ctx0#0x4': FIELD_FLAG, 'slot_ctx1#0x4': FIELD_FLAG, 'slot_ctx2#0x4': FIELD_FLAG, 'slot_ctx3#0x4': FIELD_FLAG})
xhci_94.add_flag('XHCI_SLOT_CTX.slot_ctx0', {0: 4, 8: 4, 12: 4, 16: 4, 20: 4, 24: 8})
xhci_94.add_flag('XHCI_SLOT_CTX.slot_ctx1', {0: 16, 16: 6, 22: '2@0', 24: 8})
xhci_94.add_flag('XHCI_SLOT_CTX.slot_ctx2', {0: 22, 22: 10})
xhci_94.add_flag('XHCI_SLOT_CTX.slot_ctx3', {0: 27, 27: 5})
xhci_94.add_head(['XHCI_SLOT_CTX'])
# xhci_94.add_instrumentation_point('hcd-xhci.c', ['xhci_evaluate_slot', 'xhci_dma_read_u32s', 1, 1])
# xhci_94.add_instrumentation_point('hcd-xhci.c', ['xhci_evaluate_slot', 'xhci_dma_read_u32s', 2, 1])
# xhci_94.add_instrumentation_point('hcd-xhci.c', ['xhci_reset_slot', 'xhci_dma_read_u32s', 0, 1])
# xhci_94.add_instrumentation_point('hcd-xhci.c', ['xhci_configure_slot', 'xhci_dma_read_u32s', 0, 1])
# xhci_94.add_instrumentation_point('hcd-xhci.c', ['xhci_configure_slot', 'xhci_dma_read_u32s', 2, 1])
# xhci_94.add_instrumentation_point('hcd-xhci.c', ['xhci_configure_slot', 'xhci_dma_read_u32s', 3, 1])
# xhci_94.add_instrumentation_point('hcd-xhci.c', ['xhci_address_slot', 'xhci_dma_read_u32s', 1, 1])
# xhci_94.add_instrumentation_point('hcd-xhci.c', ['usb_xhci_post_load', 'xhci_dma_read_u32s', 0, 1])
###################################################################################################################
xhci_95 = Model('xhci', 95) # 78
xhci_95.add_struct('XHCI_EP0_CTX', {
    'ep0_ctx0#0x4': FIELD_RANDOM, 'ep0_ctx1#0x4': FIELD_RANDOM, 'ep0_ctx2#0x4': FIELD_RANDOM, 'ep0_ctx3#0x4': FIELD_RANDOM, 'ep0_ctx4#0x4': FIELD_RANDOM})
xhci_95.add_head(['XHCI_EP0_CTX'])
# xhci_95.add_instrumentation_point('hcd-xhci.c', ['xhci_evaluate_slot', 'xhci_dma_read_u32s', 3, 1])
# xhci_95.add_instrumentation_point('hcd-xhci.c', ['xhci_evaluate_slot', 'xhci_dma_read_u32s', 4, 1])
# xhci_95.add_instrumentation_point('hcd-xhci.c', ['xhci_configure_slot', 'xhci_dma_read_u32s', 4, 1])
# xhci_95.add_instrumentation_point('hcd-xhci.c', ['xhci_address_slot', 'xhci_dma_read_u32s', 2, 1])
# xhci_95.add_instrumentation_point('hcd-xhci.c', ['usb_xhci_post_load', 'xhci_dma_read_u32s', 1, 1])
###################################################################################################################
uhci_79 = Model('uhci', 79)
uhci_79.add_struct('link', {'link#0x4': FIELD_POINTER | FIELD_FLAG})
uhci_79.add_flag('link.link', {0: '1@0', 1: 1})
uhci_79.add_struct('UHCI_BUF0', {'buf#0x1000': FIELD_RANDOM})
uhci_79.add_point_to('link.link', ['UHCI_BUF0'], alignment=4)
uhci_79.add_head(['link'])
# uhci_79.add_instrumentation_point('hcd-uhci.c', ['uhci_process_frame', 'pci_dma_read', 0, 1])
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
# uhci_83.add_instrumentation_point('hcd-uhci.c', ['uhci_process_frame', 'pci_dma_read', 1, 1])
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
# uhci_84.add_instrumentation_point('hcd-uhci.c', ['uhci_read_td', 'pci_dma_read', 0, 1])
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
# ohci_80.add_instrumentation_point('hcd-ohci.c', ['ohci_read_hcca', 'dma_memory_read', 0, 1])
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
# ohci_81.add_instrumentation_point('hcd-ohci.c', ['ohci_service_ed_list', 'ohci_read_ed', 0, 1])
###################################################################################################################
ehci_82 = Model('ehci', 82)
ehci_82.add_struct('list', {'list#0x4': FIELD_POINTER})
ehci_82.add_struct('list_buf', {'buf#0x1000': FIELD_RANDOM})
ehci_82.add_struct('entry', {'entry#0x4': FIELD_POINTER | FIELD_FLAG})
ehci_82.add_flag('entry.entry', {0: 1, 1: 2})
ehci_82.add_point_to('entry.entry', ['list_buf'])
ehci_82.add_point_to('list.list', ['entry'])
ehci_82.add_head(['list'])
# ehci_82.add_instrumentation_point('hcd-ehci.c', ['ehci_advance_periodic_state', 'get_dwords', 0, 1])
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
# ehci_87.add_instrumentation_point('hcd-ehci.c', ['ehci_writeback_async_complete_packet', 'get_dwords', 1, 1])
# ehci_87.add_instrumentation_point('hcd-ehci.c', ['ehci_fill_queue', 'get_dwords', 0, 1])
###################################################################################################################
ehci_89 = Model('ehci', 89)
ehci_89.add_struct('EHCIqtd_TOKEN', {'token#0x4': FIELD_FLAG})
ehci_89.add_flag('EHCIqtd_TOKEN.token', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 2, 10: 2, 12: 3, 15: 1, 16: 15, 31: 1})
ehci_89.add_head(['EHCIqtd_TOKEN'])
# ehci_89.add_instrumentation_point('hcd-ehci.c', ['ehci_state_fetchqtd', 'get_dwords', 0, 1])
###################################################################################################################
ehci_90 = Model('ehci', 90)
ehci_90.add_struct('EHCIqtd_BUF1', {'buf#0x1000': FIELD_RANDOM})
ehci_90.add_struct('EHCIqtd_NEXT', {'next#0x4': FIELD_POINTER})
ehci_90.add_point_to('EHCIqtd_NEXT.next', ['EHCIqtd_BUF1'])
ehci_90.add_head(['EHCIqtd_NEXT'])
# ehci_90.add_instrumentation_point('hcd-ehci.c', ['ehci_state_fetchqtd', 'get_dwords', 1, 1])
###################################################################################################################
ehci_91 = Model('ehci', 91)
ehci_91.add_struct('EHCIqtd_BUF2', {'buf#0x1000': FIELD_RANDOM})
ehci_91.add_struct('EHCIqtd_ALTNEXT', {'altnext#0x4': FIELD_POINTER})
ehci_91.add_point_to('EHCIqtd_ALTNEXT.altnext', ['EHCIqtd_BUF2'])
ehci_91.add_head(['EHCIqtd_ALTNEXT'])
# ehci_91.add_instrumentation_point('hcd-ehci.c', ['ehci_state_fetchqtd', 'get_dwords', 2, 1])
###################################################################################################################
ehci_92 = Model('ehci', 92)
ehci_92.add_struct('EHCIqtd_BUF3', {'buf#0x1000': FIELD_RANDOM})
ehci_92.add_struct('EHCIqtd_BUFPTRS', {
    'bufptr0#0x4': FIELD_POINTER, 'bufptr1#0x4': FIELD_POINTER, 'bufptr2#0x4': FIELD_POINTER,
    'bufptr3#0x4': FIELD_POINTER, 'bufptr4#0x4': FIELD_POINTER})
for i in range(0, 5):
    ehci_92.add_point_to('EHCIqtd_BUFPTRS.bufptr{}'.format(i), ['EHCIqtd_BUF3'])
ehci_92.add_head(['EHCIqtd_BUFPTRS'])
# ehci_92.add_instrumentation_point('hcd-ehci.c', ['ehci_state_fetchqtd', 'get_dwords', 3, 1])
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
# ehci_88.add_instrumentation_point('hcd-ehci.c', ['ehci_writeback_async_complete_packet', 'get_dwords', 0, 1])
# ehci_88.add_instrumentation_point('hcd-ehci.c', ['ehci_state_waitlisthead', 'get_dwords', 0, 1])
# ehci_88.add_instrumentation_point('hci-ehci.c', ['ehci_state_fetchqh', 'get_dwords', 0, 1])
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
# ehci_85.add_instrumentation_point('hcd-ehci.c', ['ehci_state_fetchitd', 'get_dwords', 0, 1])
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
# ehci_86.add_instrumentation_point('hcd-ehci.c', ['ehci_state_fetchsitd', 'get_dwords', 0, 1])
###################################################################################################################
dwc2_74 = Model('dwc2', 74)
dwc2_74.add_struct('DWC2_SETUP_BUF', {
    'setup_buf0#0x1': FIELD_FLAG, 'setup_buf1#0x1': FIELD_CONSTANT, 'setup_buf2#0x1': FIELD_RANDOM, 'setup_buf3#0x1': FIELD_RANDOM,
    'setup_buf4#0x1': FIELD_RANDOM, 'setup_buf5#0x1': FIELD_RANDOM, 'setup_buf6#0x1': FIELD_RANDOM, 'setup_buf7#0x1': FIELD_CONSTANT,
    'reserved_8#0x10000': FIELD_RANDOM})
dwc2_74.add_flag('DWC2_SETUP_BUF.setup_buf0', {0: 2, 2: '3@0', 5: 2, 7: 1})
dwc2_74.add_constant('DWC2_SETUP_BUF.setup_buf1', [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0x30, 0x31, 0xff, 0xfe])
dwc2_74.add_constant('DWC2_SETUP_BUF.setup_buf7', [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]) # check-and-fault-injection
# hard to infer the dependencies
dwc2_74.add_struct('DWC2_USB_MSD_CBW', {
    'sig#04': FIELD_CONSTANT, 'tag#0x4': FIELD_RANDOM, 'data_len#0x4': FIELD_FLAG,
    'flags#0x1': FIELD_FLAG, 'lun#0x1': FIELD_CONSTANT, 'cmd_len#0x1': FIELD_RANDOM, 'cmd#0x10': FIELD_RANDOM})
dwc2_74.add_head(['DWC2_SETUP_BUF', 'DWC2_USB_MSD_CBW'])
dwc2_74.add_constant('DWC2_USB_MSD_CBW.sig', [0x43425355, 0x0])
dwc2_74.add_constant('DWC2_USB_MSD_CBW.lun', [0, 1])
dwc2_74.add_flag('DWC2_USB_MSD_CBW.data_len', {0: 2, 2: '28@0', 30: 2})
dwc2_74.add_flag('DWC2_USB_MSD_CBW.flags', {0: 7, 7: 1})
# dwc2_74.add_instrumentation_point('hcd-dwc2.c', ['dwc2_handle_packet', 'dma_memory_read', 0, 1])
###################################################################################################################
