from videzzo_types_lib import Model
from videzzo_types_lib import FIELD_RANDOM, FIELD_FLAG, FIELD_POINTER, FIELD_CONSTANT

ac97_00 = Model('ac97', 0)
ac97_00.add_struct('BD', {'addr#0x4': FIELD_POINTER, 'ctl_len#0x4': FIELD_RANDOM})
ac97_00.add_struct('AC97_TEMP_BUF', {'temp#0x1000': FIELD_RANDOM})
# ac97_00.add_context_tag_to_point_to('BD.addr', '& ~3')
ac97_00.add_context_flag_to_point_to(None, 'BD.addr', ['AC97_TEMP_BUF'])
ac97_00.add_head(['BD'], ['fetch_bd', 'pci_dma_read'])
###################################################################################################################
# cs4231a: implicit address in k->read_memory: keep its id: 1: corner case
###################################################################################################################
es1370_02 = Model('es1370', 2)
es1370_02.add_struct('ES1370_TEMP_BUF', {'temp#0x1000': FIELD_RANDOM})
es1370_02.add_head(['ES1370_TEMP_BUF'], ['es1370_transfer_audio', 'pci_dma_read'])
###################################################################################################################
intel_hda_03 = Model('intel_hda', 3)
intel_hda_03.add_struct('INTEL_HDA_BUF', {'addr#0x8': FIELD_POINTER, 'len#0x4': FIELD_CONSTANT, 'flags#0x4': FIELD_FLAG})
intel_hda_03.add_struct('TMP', {'tmp#0x1000': FIELD_RANDOM})
intel_hda_03.add_context_flag_to_point_to(None, 'INTEL_HDA_BUF.addr', ['TMP'])
intel_hda_03.add_constant('INTEL_HDA_BUF.len', 4096)
intel_hda_03.add_flag('INTEL_HDA_BUF.flags', {0: 1, 1: 31})
intel_hda_03.add_head(['INTEL_HDA_BUF'], ['ntel_hda_parse_bdl', 'pci_dma_read'])
intel_hda_04 = Model('intel_hda', 4)
intel_hda_04.add_struct('VERB', {'verb#0x4': FIELD_FLAG})
intel_hda_04.add_flag('VERB.verb', {0: 8, 8: 12, 20: 7, 27: 1, 28: 4})
intel_hda_04.add_head(['VERB'], ['intel_hda_corb_run', 'ldl_le_pci_dma'])
###################################################################################################################
# sb_16: does have any dma accesses: keep its id: 5
###################################################################################################################
eepro100_06 = Model('eepro100', 6)
eepro100_tx = {
    'status#0x2': FIELD_FLAG,
    'command#0x2': FIELD_FLAG,
    'link#0x4': FIELD_RANDOM,
    'tbd_array_addr#0x4': FIELD_POINTER,
    'tcb_bytes#0x2': FIELD_RANDOM,
    'tx_threshold#0x1': FIELD_RANDOM,
    'tbd_count#0x1': FIELD_RANDOM,
    'tx_buf_addr0#0x4': FIELD_POINTER,
    'tx_buf_size0#0x4': FIELD_FLAG,
    'tx_buf_addr1#0x4': FIELD_POINTER,
    'tx_buf_size1#0x4': FIELD_FLAG,
}
eepro100_06.add_struct('EEPRO100_TX', eepro100_tx)
eepro100_06.add_flag('EEPRO100_TX.status', {0: 13, 13: 1, 14: 1, 15: 1})
eepro100_06.add_flag('EEPRO100_TX.command', {0: 3, 3: 1, 4: 1, 5: 8, 13: 1, 14: 1, 15: 1})
eepro100_06.add_flag('EEPRO100_TX.tx_buf_size0', {0: 16, 16: 16})
eepro100_06.add_flag('EEPRO100_TX.tx_buf_size1', {0: 16, 16: 16})
eepro100_06.add_struct('EEPRO100_TX_BUF', {'buf#0xa28': FIELD_RANDOM})
eepro100_06.add_struct('MAC_ADDR', {
    'mac_addr0#0x1': FIELD_RANDOM, 'mac_addr1#0x1': FIELD_RANDOM, 'mac_addr2#0x1': FIELD_RANDOM,
    'mac_addr3#0x1': FIELD_RANDOM, 'mac_addr4#0x1': FIELD_RANDOM, 'mac_addr5#0x1': FIELD_RANDOM})
eepro100_configuration = {}
for i in range(0, 22):
    eepro100_configuration['configuration{}#0x1'.format(i)] = FIELD_RANDOM
eepro100_06.add_struct('CONFIGURATION', eepro100_configuration)
for i in range(0, 22):
    eepro100_06.add_flag('CONFIGURATION.configuration{}'.format(i), {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1})
eepro100_06.add_struct('TX_BUF', {'tx_buf_addr#0x4': FIELD_POINTER, 'tx_buf_size#0x2': FIELD_RANDOM, 'tx_buf_el#0x2': FIELD_RANDOM})
eepro100_06.add_context_flag_to_point_to(None, 'TX_BUF.tx_buf_addr', ['EEPRO100_TX_BUF'])
eepro100_06.add_context_flag_to_point_to(None, 'EEPRO100_TX.tx_buf_addr0', ['EEPRO100_TX_BUF'])
eepro100_06.add_context_flag_to_point_to(None, 'EEPRO100_TX.tx_buf_addr1', ['EEPRO100_TX_BUF'])
eepro100_06.add_context_flag_to_point_to(['EEPRO100_TX.command.0'], 'EEPRO100_TX.tbd_array_addr', [
    'EEPRO100_TX_BUF', # 0
    'MAC_ADDR', # 1
    'CONFIGURATION', # 2
    'EEPRO100_TX_BUF', # 3: set_multicast_list: corner case
    'TX_BUF', # 4
    'EEPRO100_TX_BUF', # 5
    'EEPRO100_TX_BUF', # 6
    'EEPRO100_TX_BUF', # 7
])
eepro100_06.add_head(['EEPRO100_TX'], ['read_cb', 'pci_dma_read'])
# eepro100_07: no need to instrument: eepro100_write_port, pci_dma_read: keep its id: 7
eepro100_08 = Model('eepro100', 8)
eepro100_rx = {
    'status#0x2': FIELD_FLAG,
    'command#0x2': FIELD_FLAG,
    'link#0x4': FIELD_RANDOM,
    'rx_buf_addr#0x4': FIELD_POINTER,
    'count#0x2': FIELD_RANDOM,
    'size#0x2': FIELD_RANDOM,
}
eepro100_08.add_struct('EEPRO100_RX', eepro100_rx)
eepro100_08.add_flag('EEPRO100_RX.status', {0: 13, 13: 1, 14: 1, 15: 1})
eepro100_08.add_flag('EEPRO100_RX.command', {0: 3, 3: 1, 4: 1, 5: 8, 13: 1, 14: 1, 15: 1})
eepro100_08.add_struct('EEPRO100_RX_BUF', {'buf#0x1000': FIELD_RANDOM})
eepro100_08.add_context_flag_to_point_to(None, 'EEPRO100_RX.rx_buf_addr', ['EEPRO100_RX_BUF'])
eepro100_08.add_head(['EEPRO100_RX'], ['nic_receive', 'pci_read_dma'])
###################################################################################################################
e1000e_09 = Model('e1000e', 9)
# corner case: union can be two different data!
e1000_tx_desc = {'buffer_addr#0x8': FIELD_POINTER, 'flags#0x4': FIELD_FLAG, 'fields#0x4': FIELD_FLAG}
e1000e_09.add_struct('E1000_TX_DESC', e1000_tx_desc)
e1000e_09.add_flag('E1000_TX_DESC.flags', {0: 8, 8: 8, 16: 16})
e1000e_09.add_flag('E1000_TX_DESC.fields', {0: 16, 16: 8, 24: 16})
e1000e_09.add_struct('E1000E_BUF', {'buf#0x1000': FIELD_RANDOM})
e1000e_09.add_context_flag_to_point_to(None, 'E1000_TX_DESC.buffer_addr', ['E1000E_BUF'])
e1000e_09.add_head(['E1000_TX_DESC'], ['e1000e_start_xmit', 'pci_dma_read'])
e1000e_10 = Model('e1000e', 10)
# corner case: union can be data or pointer at the same time!
e1000e_10.add_struct('DESC', {'buffer_addr0#0x20': FIELD_RANDOM})
e1000e_10.add_head(['DESC'], ['e1000e_start_xmit', 'pci_dma_read'])
###################################################################################################################
# ne2000: does have any dma accesses: keep its id: 11
###################################################################################################################
# sometimes, MorPhuzz and VShuttle are the same with ViDeZZo regarding the "context-aware"
pcnet_12 = Model('pcnet', 12)
pcnet_12.add_struct('PCNET_XDA', {'tbadr#0x4': FIELD_POINTER, 'length#0x2': FIELD_RANDOM, 'status#0x2': FIELD_RANDOM})
pcnet_12.add_struct('PCNET_BUF0', {'buf#0x1000': FIELD_RANDOM})
pcnet_12.add_context_flag_to_point_to(None, 'PCNET_XDA.tbadr', ['PCNET_BUF0'])
pcnet_12.add_head(['PCNET_XDA'], ['pcnet_tmd_load', 's->phys_mem_read.0'])
pcnet_13 = Model('pcnet', 13)
pcnet_13.add_struct('PCNET_TMD', {'tbadr#0x4': FIELD_POINTER, 'length#0x2': FIELD_RANDOM, 'status#0x2': FIELD_FLAG, 'misc#0x4': FIELD_FLAG, 'res#0x4': FIELD_RANDOM})
pcnet_13.add_struct('PCNET_BUF1', {'buf#0x1000': FIELD_RANDOM})
pcnet_13.add_context_flag_to_point_to(None, 'PCNET_TMD.tbadr', ['PCNET_BUF1'])
pcnet_13.add_flag('PCNET_TMD.status', {0: 7, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 15: 1, 16: 16})
# cornel case: data and pointer are exchangeable
pcnet_13.add_flag('PCNET_TMD.misc', {0: 4, 4: 12, 16: 10, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
pcnet_13.add_head(['PCNET_TMD'], ['pcnet_tmd_load', 's->phys_mem_read.1'])
pcnet_14 = Model('pcnet', 14)
pcnet_14.add_struct('PCNET_RDA', {'rbadr#0x4': FIELD_POINTER, 'buf_length#0x2': FIELD_RANDOM, 'msg_length#0x2': FIELD_RANDOM})
pcnet_14.add_struct('PCNET_BUF2', {'buf#0x1000': FIELD_RANDOM})
pcnet_14.add_context_flag_to_point_to(None, 'PCNET_RDA.rbadr', ['PCNET_BUF2'])
pcnet_14.add_head(['PCNET_RDA'], ['pcnet_rmd_load', 's->phys_mem_read.0'])
pcnet_15 = Model('pcnet', 15)
pcnet_15.add_struct('PCNET_RMD', {'rbadr#0x4': FIELD_POINTER, 'buf_length#0x2': FIELD_RANDOM, 'status#0x2': FIELD_FLAG, 'msg_length#0x4': FIELD_FLAG, 'res#0x4': FIELD_RANDOM})
pcnet_15.add_flag('PCNET_RMD.status', {0: 4, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 12: 1, 13: 1, 14: 1, 15: 1, 16: 16})
# cornel case: data and pointer are exchangeable
pcnet_15.add_flag('PCNET_RMD.msg_length', {0: 12, 12: 4, 16: 8, 24: 8})
pcnet_15.add_struct('PCNET_BUF3', {'buf#0x1000': FIELD_RANDOM})
pcnet_15.add_context_flag_to_point_to(None, 'PCNET_RMD.rbadr', ['PCNET_BUF3'])
pcnet_15.add_head(['PCNET_RMD'], ['pcnet_rmd_load', 's->phys_mem_read.1'])
pcnet_16 = Model('pcnet', 16)
pcnet_16.add_struct('PCNET_INITBLK32', {
    'mode#0x2': FIELD_RANDOM, 'rlen#0x1': FIELD_RANDOM, 'tlen#0x1': FIELD_RANDOM, 'padr0#0x2': FIELD_RANDOM,
    'padr1#0x2': FIELD_RANDOM, 'padr2#0x2': FIELD_RANDOM, '_res#0x2': FIELD_RANDOM, 'ladrf0#0x2': FIELD_RANDOM,
    'ladrf1#0x2': FIELD_RANDOM, 'ladrf2#0x2': FIELD_RANDOM, 'ladrf3#0x2': FIELD_RANDOM, 'rdra#0x4': FIELD_RANDOM,
    'tdra#0x4': FIELD_RANDOM})
pcnet_16.add_head(['PCNET_INITBLK32'], ['pcnet_init', 's->phys_mem_read.0'])
pcnet_17 = Model('pcnet', 17)
pcnet_17.add_struct('PCNET_INITBLK16', {
    'mode#0x2': FIELD_RANDOM, 'padr0#0x2': FIELD_RANDOM, 'padr1#0x2': FIELD_RANDOM, 'padr2#0x2': FIELD_RANDOM,
    'ladrf0#0x2': FIELD_RANDOM, 'ladrf1#0x2': FIELD_RANDOM, 'ladrf2#0x2': FIELD_RANDOM, 'ladrf3#0x2': FIELD_RANDOM,
    'rdra#0x4': FIELD_RANDOM, 'tdra#0x4': FIELD_RANDOM})
pcnet_17.add_head(['PCNET_INITBLK16'], ['pcnet_init', 's->phys_mem_read.1'])
###################################################################################################################
###################################################################################################################
# floppy: implicit address in k->read_memory: keep its id 6: corner case
###################################################################################################################
