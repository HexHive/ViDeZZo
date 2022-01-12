from videzzo_types_lib import Model
from videzzo_types_lib import FIELD_RANDOM, FIELD_FLAG, FIELD_POINTER, FIELD_CONSTANT
from videzzo_types_lib import dict_append

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
intel_hda_03.add_struct('INTEL_HDA_BUF', {'addr#0x8': FIELD_POINTER, 'len#0x4': FIELD_RANDOM, 'flags#0x4': FIELD_FLAG})
intel_hda_03.add_struct('TMP', {'tmp#0x1000': FIELD_RANDOM})
intel_hda_03.add_context_flag_to_point_to(None, 'INTEL_HDA_BUF.addr', ['TMP'])
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
rtl8139_18 = Model('rtl8139', 18)
rtl8139_18.add_struct('RTL8139_RX_RING_DESC', {
    'rxdw0#0x4': FIELD_FLAG, 'rxdw1#0x4': FIELD_RANDOM, 'rxbuf#0x8': FIELD_POINTER})
rtl8139_18.add_flag('RTL8139_RX_RING_DESC.rxdw0', {0: 13, 13: 1, 14: 1, 15: 1, 16: 1, 17: 1, 18: 1, 19: 1, 20: 4, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
rtl8139_18.add_struct('RTL8139_RX_RING_DESC_BUF', {'buf#0x1000': FIELD_RANDOM})
rtl8139_18.add_context_flag_to_point_to(None, 'RTL8139_RX_RING_DESC.rxbuf', ['RTL8139_RX_RING_DESC_BUF'])
rtl8139_18.add_head(['RTL8139_RX_RING_DESC'], ['rtl8139_do_receive', 'pci_dma_read.0'])
rtl8139_19 = Model('rtl8139', 19)
rtl8139_19.add_struct('RTL8139_TX_RING_DESC', {
    'txdw0#0x4': FIELD_FLAG, 'txdw1#0x4': FIELD_FLAG, 'txbuf#0x8': FIELD_POINTER})
rtl8139_19.add_flag('RTL8139_TX_RING_DESC.txdw0', {0: 16, 16: 1, 17: 1, 18: 9, 27: 1, 28: 1, 29: 1, 30: 1, 31: 1})
rtl8139_19.add_flag('RTL8139_TX_RING_DESC.txdw1', {0: 16, 16: 1, 17: 1, 18: 14})
rtl8139_19.add_struct('RTL8139_TX_RING_DESC_BUF', {'buf#0x1000': FIELD_RANDOM})
rtl8139_19.add_context_flag_to_point_to(None, 'RTL8139_TX_RING_DESC.txbuf', ['RTL8139_TX_RING_DESC_BUF'])
rtl8139_19.add_head(['RTL8139_TX_RING_DESC'], ['rtl8139_cplus_transmit_one', 'pci_dma_read.0'])
rtl8139_20 = Model('rtl8139', 20)
rtl8139_20.add_struct('RTL8139_BUF', {'buf#0x2000': FIELD_RANDOM})
rtl8139_20.add_head(['RTL8139_BUF'], ['rtl8139_transmit_one', 'pci_dam_read.0'])
###################################################################################################################
vmxnet3_21 = Model('vmxnet3', 21)
# union: corner case: big endian and little endian
vmxnet3_21.add_struct('Vmxnet3_TxDesc', {'addr#0x8': FIELD_POINTER, 'val1#0x4': FIELD_FLAG, 'val2#0x4': FIELD_FLAG})
vmxnet3_21.add_context_flag_to_point_to(None, 'Vmxnet3_TxDesc.addr', ['Vmxnet3_TxDesc'])
vmxnet3_21.add_flag('Vmxnet3_TxDesc.val1', {0: 14, 14: 1, 15: 1, 16: 1, 17: 1, 18: 14})
vmxnet3_21.add_flag('Vmxnet3_TxDesc.val2', {0: 10, 10: 2, 12: 1, 13: 1, 14: 1, 15: 1, 16: 16})
vmxnet3_21.add_struct('Vmxnet3_TxCompDesc', {'val1#0x4': FIELD_FLAG, 'ext2#0x4': FIELD_RANDOM, 'ext3#0x4': FIELD_RANDOM, 'val2#0x4': FIELD_FLAG})
vmxnet3_21.add_flag('Vmxnet3_TxCompDesc.val1', {0: 12, 12: 20})
vmxnet3_21.add_flag('Vmxnet3_TxCompDesc.val2', {0: 24, 24: 7, 31: 1})

Vmxnet3_TxQueueDesc = {}
Vmxnet3_TxQueueCtrl = {'txNumDeferred#0x4': FIELD_RANDOM, 'txThreshold#0x4': FIELD_RANDOM, 'reserved_0#0x8': FIELD_RANDOM}
dict_append(Vmxnet3_TxQueueDesc, Vmxnet3_TxQueueCtrl)
Vmxnet3_TxQueueConf = {'txRingBasePA#0x8': FIELD_POINTER, 'dataRingBasePA#0x8': FIELD_RANDOM, # dataRingBasePA never used
                       'compRingBasePA#0x8': FIELD_POINTER, 'ddPA#0x8': FIELD_RANDOM, 'reserved_1#0x8': FIELD_RANDOM,
                       'txRingSize#0x4': FIELD_RANDOM, 'dataRingSize#0x4': FIELD_RANDOM, 'compRingSize#0x4': FIELD_RANDOM,
                       'ddLen#0x4': FIELD_RANDOM, 'intrIdx#0x1': FIELD_RANDOM, '_pad_0#0x7': FIELD_RANDOM}
dict_append(Vmxnet3_TxQueueDesc, Vmxnet3_TxQueueConf)
Vmxnet3_QueueStatus = {'stopped#0x1': FIELD_RANDOM, '_pad_1#0x3': FIELD_RANDOM, 'reserved_2#0x8': FIELD_RANDOM}
dict_append(Vmxnet3_TxQueueDesc, Vmxnet3_QueueStatus)
UPT1_RxStats = {'LROPktsRxOK#0x8': FIELD_RANDOM, 'LROBytesRxOK#0x8': FIELD_RANDOM, 'ucastPktsRxOK#0x8': FIELD_RANDOM, 'ucastBytesRxOK#0x8': FIELD_RANDOM,
                'mcastPktsRxOK#0x8': FIELD_RANDOM, 'mcastBytesRxOK#0x8': FIELD_RANDOM, 'bcastPktsRxOK#0x8': FIELD_RANDOM, 'bcastBytesRxOK#0x8': FIELD_RANDOM,
                'pktsRxOutOfBuf#0x8': FIELD_RANDOM, 'pktsRxError#0x8': FIELD_RANDOM}
dict_append(Vmxnet3_TxQueueDesc, UPT1_RxStats)
dict_append(Vmxnet3_TxQueueDesc, {'_pad_2#0x88': FIELD_RANDOM})
vmxnet3_21.add_struct('Vmxnet3_TxQueueDesc', Vmxnet3_TxQueueDesc)
# not very clear if this a ring
vmxnet3_21.add_context_flag_to_single_linked_list(None, 'Vmxnet3_TxQueueDesc.txRingBasePA', ['Vmxnet3_TxDesc'], ['addr'])
# not very clear if this a ring
vmxnet3_21.add_context_flag_to_point_to(None, 'Vmxnet3_TxQueueDesc.compRingBasePA', ['Vmxnet3_TxCompDesc'])

vmxnet3_21.add_struct('Vmxnet3_MACADDR', {'addr0#0x1': FIELD_RANDOM, 'addr1#0x1': FIELD_RANDOM, 'addr2#0x1': FIELD_RANDOM,
                                          'addr3#0x1': FIELD_RANDOM, 'addr4#0x1': FIELD_RANDOM, 'addr5#0x1': FIELD_RANDOM})
Vmxnet3_DriverShared = {}
Vmxnet3_DriverShared_p1 = {'magic#0x4': FIELD_CONSTANT, 'pad_3#0x4': FIELD_RANDOM}
dict_append(Vmxnet3_DriverShared, Vmxnet3_DriverShared_p1)
Vmxnet3_DSDevRead = {}
Vmxnet3_MiscConf = {}
Vmxnet3_DriverInfo = {'version#0x4': FIELD_RANDOM, 'gos#0x4': FIELD_FLAG, 'vmxnet3RevSpt#0x4': FIELD_RANDOM, 'uptVerSpt#0x4': FIELD_RANDOM}
dict_append(Vmxnet3_MiscConf, Vmxnet3_DriverInfo)
Vmxnet3_MiscConf_p1 = {'uptFeature#0x8': FIELD_RANDOM, 'ddPA#0x8': FIELD_RANDOM, 'queueDescPA#0x8': FIELD_POINTER, 'ddLen#0x4': FIELD_RANDOM,
                       'queueDescLen#0x4': FIELD_RANDOM, 'mtu#0x4': FIELD_RANDOM, 'maxNumRxSG#0x2': FIELD_RANDOM, 'numTxQueues#0x1': FIELD_RANDOM,
                       'numRxQueues#0x1': FIELD_RANDOM, 'reserved_3#0x10': FIELD_RANDOM}
dict_append(Vmxnet3_MiscConf, Vmxnet3_MiscConf_p1)
dict_append(Vmxnet3_DSDevRead, Vmxnet3_MiscConf)
Vmxnet3_IntrConf = {'autoMask#0x1': FIELD_RANDOM, 'numIntrs#0x1': FIELD_RANDOM, 'eventIntrIdx#0x1': FIELD_RANDOM, 'modLevels#0x19': FIELD_RANDOM,
                    'intrCtrl#0x4': FIELD_RANDOM, 'reserved_4#0x8': FIELD_RANDOM}
dict_append(Vmxnet3_DSDevRead, Vmxnet3_IntrConf)
Vmxnet3_RxFilterConf = {'rxMode#0x4': FIELD_RANDOM, 'mfTableLen#0x2': FIELD_RANDOM, '_pad_4#0x2': FIELD_RANDOM,
                        'mfTablePA#0x8': FIELD_POINTER, 'vfTable#0x2000': FIELD_RANDOM}
dict_append(Vmxnet3_DSDevRead, Vmxnet3_RxFilterConf)
Vmxnet3_VariableLenConfDesc0 = {'confVer_0#0x4': FIELD_RANDOM, 'confLen_0#0x4': FIELD_RANDOM, 'confPA_0#0x8': FIELD_RANDOM} # confPA is never used
Vmxnet3_VariableLenConfDesc1 = {'confVer_1#0x4': FIELD_RANDOM, 'confLen_1#0x4': FIELD_RANDOM, 'confPA_1#0x8': FIELD_RANDOM} # confPA is never used
Vmxnet3_VariableLenConfDesc2 = {'confVer_2#0x4': FIELD_RANDOM, 'confLen_2#0x4': FIELD_RANDOM, 'confPA_2#0x8': FIELD_RANDOM} # confPA is never used
dict_append(Vmxnet3_DSDevRead, Vmxnet3_VariableLenConfDesc0)
dict_append(Vmxnet3_DSDevRead, Vmxnet3_VariableLenConfDesc1)
dict_append(Vmxnet3_DSDevRead, Vmxnet3_VariableLenConfDesc2)
dict_append(Vmxnet3_DriverShared, Vmxnet3_DSDevRead)
Vmxnet3_DriverShared_p2 = {'ecr#0x4': FIELD_RANDOM, 'reserved_5#0x14': FIELD_RANDOM}
dict_append(Vmxnet3_DriverShared, Vmxnet3_DriverShared_p2)
vmxnet3_21.add_struct('Vmxnet3_DriverShared', Vmxnet3_DriverShared)
vmxnet3_21.add_flag('Vmxnet3_DriverShared.gos', {0: 2, 2: 4, 6: 16, 22: 10})
vmxnet3_21.add_constant('Vmxnet3_DriverShared.magic', 0xbabefee1)
# this is an array list: need more implementation
vmxnet3_21.add_context_flag_to_point_to(None, 'Vmxnet3_DriverShared.queueDescPA', ['Vmxnet3_TxQueueDesc'])
# this is an array list: need more implementation
vmxnet3_21.add_context_flag_to_point_to(None, 'Vmxnet3_DriverShared.mfTablePA', ['Vmxnet3_MACADDR'])
vmxnet3_21.add_head(['Vmxnet3_DriverShared'], ['vmxnet3_activate_device', 'vmxnet3_verify_driver_magic'])
###################################################################################################################
# floppy: implicit address in k->read_memory: keep its id: 22: corner case
###################################################################################################################
# ahci: sglist: keep its id: 23/24/25: corner case
###################################################################################################################
sdhci_26 = Model('sdhci', 26)
sdhci_26.add_struct('adma2', {'attr#1': FIELD_RANDOM, 'reserved#1': FIELD_RANDOM, 'length#0x2': FIELD_RANDOM, 'addr#0x4': FIELD_POINTER})
sdhci_26.add_struct('adma2_buf', {'buf#0x1000': FIELD_RANDOM})
sdhci_26.add_context_flag_to_point_to(None, 'adma2.addr', ['adma2_buf'])
sdhci_26.add_head(['adma2'], ['get_adma_description', 'dma_memory_read.0'])
sdhci_27 = Model('sdhci', 27)
# corner case: non-aligned address
sdhci_27.add_struct('adma1', {'adma1#0x4': FIELD_POINTER})
sdhci_27.add_flag('adma1.adma1', {0: 7, 8: 12, 12: 20})
sdhci_27.add_struct('adma1_buf', {'buf#0x1000': FIELD_RANDOM})
sdhci_27.add_context_flag_to_point_to(None, 'adma1.adma1', ['adma1_buf'])
sdhci_27.add_head(['adma1'], ['get_adma_description', 'dma_memory_read.1'])
sdhci_28 = Model('sdhci', 28)
sdhci_28.add_struct('adma2_64', {'attr#1': FIELD_RANDOM, 'reserved#1': FIELD_RANDOM, 'length#0x2': FIELD_RANDOM, 'addr#0x8': FIELD_POINTER})
sdhci_28.add_struct('adma2_64_buf', {'buf#0x1000': FIELD_RANDOM})
sdhci_28.add_context_flag_to_point_to(None, 'adma2_64.addr', ['adma2_64_buf'])
sdhci_28.add_head(['adma2_64'], ['get_adma_description', 'dma_memory_read.2'])
sdhci_29 = Model('sdhci', 29)
sdhci_29.add_struct('fifo_buffer_0', {'buf#0x1000': FIELD_RANDOM})
sdhci_29.add_head(['fifo_buffer_0'], ['sdhci_sdma_transfer_single_block', 'dma_memory_read'])
sdhci_30 = Model('sdhci', 30)
sdhci_30.add_struct('fifo_buffer_1', {'buf#0x1000': FIELD_RANDOM})
sdhci_30.add_head(['fifo_buffer_1'], ['sdhci_sdma_transfer_single_block', 'dma_memory_read'])
###################################################################################################################
#xhci_address_slot: 11
xhci_31 = Model('xhci', 31)
xhci_31.add_struct('ictrl_ctx11', {
    'ictrl_ctx0#0x4': FIELD_CONSTANT, 'ictrl_ctx1#0x4': FIELD_CONSTANT, 'reserved#0x24': FIELD_RANDOM,
    'slot_ctx0#0x4': FIELD_FLAG, 'slot_ctx1#0x4': FIELD_FLAG, 'slot_ctx2#0x4': FIELD_FLAG, 'slot_ctx3#0x4': FIELD_FLAG, 'reserved#0x10': FIELD_RANDOM,
    'ep0_ctx0#0x4': FIELD_RANDOM, 'ep0_ctx1#0x4': FIELD_RANDOM, 'ep0_ctx2#0x4': FIELD_RANDOM, 'ep0_ctx3#0x4': FIELD_RANDOM, 'ep0_ctx4#0x4': FIELD_RANDOM})
xhci_31.add_constant('ictrl_ctx11.ictrl_ctx0', 0)
xhci_31.add_constant('ictrl_ctx11.ictrl_ctx1', 3)
xhci_31.add_flag('ictrl_ctx11.slot_ctx0', {0: 4, 8: 4, 12: 4, 16: 4, 20: 4, 24: 8})
xhci_31.add_flag('ictrl_ctx11.slot_ctx1', {0: 16, 16: 8, 24: 8})
xhci_31.add_flag('ictrl_ctx11.slot_ctx2', {0: 22, 22: 10})
xhci_31.add_flag('ictrl_ctx11.slot_ctx3', {0: 27, 27: 5})
#xhci_configure_slot: 12
xhci_31.add_struct('ictrl_ctx12', {
    'ictrl_ctx0#0x4': FIELD_FLAG, 'ictrl_ctx1#0x4': FIELD_FLAG, 'reserved#0x24': FIELD_RANDOM,
    'islot_ctx0#0x4': FIELD_RANDOM, 'islot_ctx1#0x4': FIELD_RANDOM, 'islot_ctx2#0x4': FIELD_RANDOM, 'islot_ctx3#0x4': FIELD_RANDOM, 'reserved#0x10': FIELD_RANDOM,
    'ep_ctx0#0x20': FIELD_RANDOM, 'ep_ctx1#0x20': FIELD_RANDOM, 'ep_ctx2#0x20': FIELD_RANDOM, 'ep_ctx3#0x20': FIELD_RANDOM, 'ep_ctx4#0x20': FIELD_RANDOM,
    'ep_ctx5#0x20': FIELD_RANDOM, 'ep_ctx6#0x20': FIELD_RANDOM, 'ep_ctx7#0x20': FIELD_RANDOM, 'ep_ctx8#0x20': FIELD_RANDOM, 'ep_ctx9#0x20': FIELD_RANDOM,
    'ep_ctx10#0x20': FIELD_RANDOM, 'ep_ctx11#0x20': FIELD_RANDOM, 'ep_ctx12#0x20': FIELD_RANDOM, 'ep_ctx13#0x20': FIELD_RANDOM, 'ep_ctx14#0x20': FIELD_RANDOM,
    'ep_ctx15#0x20': FIELD_RANDOM, 'ep_ctx16#0x20': FIELD_RANDOM, 'ep_ctx17#0x20': FIELD_RANDOM, 'ep_ctx18#0x20': FIELD_RANDOM, 'ep_ctx19#0x20': FIELD_RANDOM,
    'ep_ctx20#0x20': FIELD_RANDOM, 'ep_ctx21#0x20': FIELD_RANDOM, 'ep_ctx22#0x20': FIELD_RANDOM, 'ep_ctx23#0x20': FIELD_RANDOM, 'ep_ctx24#0x20': FIELD_RANDOM,
    'ep_ctx25#0x20': FIELD_RANDOM, 'ep_ctx26#0x20': FIELD_RANDOM, 'ep_ctx27#0x20': FIELD_RANDOM, 'ep_ctx28#0x20': FIELD_RANDOM, 'ep_ctx29#0x20': FIELD_RANDOM,
})
xhci_31.add_flag('ictrl_ctx12.ictrl_ctx0', {0: '2@3', 2: 30})
xhci_31.add_flag('ictrl_ctx12.ictrl_ctx1', {0: '2@3', 2: 30})
#xhci_evaluate_slot: 13
xhci_31.add_struct('ictrl_ctx13', {
    'ictrl_ctx0#0x4': FIELD_CONSTANT, 'ictrl_ctx1#0x4': FIELD_FLAG, 'reserved#0x24': FIELD_RANDOM,
    'islot_ctx#0x20': FIELD_RANDOM, 'ep0_ctx#0x20': FIELD_RANDOM
})
xhci_31.add_constant('ictrl_ctx13.ictrl_ctx0', 0)
xhci_31.add_flag('ictrl_ctx13.ictrl_ctx1', {0: 2, 2: '30@0'})
xhci_31.add_struct('XHCITRB', {'parameter#0x8': FIELD_POINTER, 'status#0x4': FIELD_FLAG, 'control#0x4': FIELD_FLAG, 'addr#0x8': FIELD_RANDOM, 'ccs#0x1': FIELD_RANDOM})
xhci_31.add_struct('XHCITRB1', {'parameter#0x8': FIELD_POINTER, 'status#0x4': FIELD_FLAG, 'control#0x4': FIELD_FLAG, 'addr#0x8': FIELD_RANDOM, 'ccs#0x1': FIELD_RANDOM})
xhci_31.add_flag('XHCITRB.control', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 2, 9: 1, 10: 6, 16: 5, 21: 3, 24: 8})
xhci_31.add_flag('XHCITRB.status', {0: 16, 16: 6, 22: 10})
xhci_31.add_flag('XHCITRB1.control', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 2, 9: 1, 10: 6, 16: 5, 21: 3, 24: 8})
xhci_31.add_flag('XHCITRB1.status', {0: 16, 16: 6, 22: 10})
xhci_31.add_context_flag_to_point_to(['XHCITRB1.control.10'], 'XHCITRB1.parameter', [
    None, None, None, None, None, None, None, None, None, None, None, 'ictrl_ctx11', 'ictrl_ctx12', 'ictrl_ctx13', None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
])
xhci_31.add_context_flag_to_point_to(['XHCITRB.control.10'], 'XHCITRB.parameter', [
    None, None, None, None, None, None, 'XHCITRB1', None, None, None, None, 'ictrl_ctx11', 'ictrl_ctx12', 'ictrl_ctx13', None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
])
xhci_31.add_head(['XHCITRB'], ['xhci_ring_fetch', 'pci_dma_read'])
xhci_32 = Model('xhci', 32)
xhci_32.add_struct('XHCIEvRingSeg', {'addr#0x8': FIELD_POINTER, 'size#0x4': FIELD_RANDOM, 'rsvd#0x4': FIELD_RANDOM})
xhci_32.add_struct('ictrl_ctx11_1', {
    'ictrl_ctx0#0x4': FIELD_CONSTANT, 'ictrl_ctx1#0x4': FIELD_CONSTANT, 'reserved#0x24': FIELD_RANDOM,
    'slot_ctx0#0x4': FIELD_FLAG, 'slot_ctx1#0x4': FIELD_FLAG, 'slot_ctx2#0x4': FIELD_FLAG, 'slot_ctx3#0x4': FIELD_FLAG, 'reserved#0x10': FIELD_RANDOM,
    'ep0_ctx0#0x4': FIELD_RANDOM, 'ep0_ctx1#0x4': FIELD_RANDOM, 'ep0_ctx2#0x4': FIELD_RANDOM, 'ep0_ctx3#0x4': FIELD_RANDOM, 'ep0_ctx4#0x4': FIELD_RANDOM})
xhci_32.add_constant('ictrl_ctx11_1.ictrl_ctx0', 0)
xhci_32.add_constant('ictrl_ctx11_1.ictrl_ctx1', 3)
xhci_32.add_flag('ictrl_ctx11_1.slot_ctx0', {0: 4, 8: 4, 12: 4, 16: 4, 20: 4, 24: 8})
xhci_32.add_flag('ictrl_ctx11_1.slot_ctx1', {0: 16, 16: 8, 24: 8})
xhci_32.add_flag('ictrl_ctx11_1.slot_ctx2', {0: 22, 22: 10})
xhci_32.add_flag('ictrl_ctx11_1.slot_ctx3', {0: 27, 27: 5})
#xhci_configure_slot: 12
xhci_32.add_struct('ictrl_ctx12_1', {
    'ictrl_ctx0#0x4': FIELD_FLAG, 'ictrl_ctx1#0x4': FIELD_FLAG, 'reserved#0x24': FIELD_RANDOM,
    'islot_ctx0#0x4': FIELD_RANDOM, 'islot_ctx1#0x4': FIELD_RANDOM, 'islot_ctx2#0x4': FIELD_RANDOM, 'islot_ctx3#0x4': FIELD_RANDOM, 'reserved#0x10': FIELD_RANDOM,
    'ep_ctx0#0x20': FIELD_RANDOM, 'ep_ctx1#0x20': FIELD_RANDOM, 'ep_ctx2#0x20': FIELD_RANDOM, 'ep_ctx3#0x20': FIELD_RANDOM, 'ep_ctx4#0x20': FIELD_RANDOM,
    'ep_ctx5#0x20': FIELD_RANDOM, 'ep_ctx6#0x20': FIELD_RANDOM, 'ep_ctx7#0x20': FIELD_RANDOM, 'ep_ctx8#0x20': FIELD_RANDOM, 'ep_ctx9#0x20': FIELD_RANDOM,
    'ep_ctx10#0x20': FIELD_RANDOM, 'ep_ctx11#0x20': FIELD_RANDOM, 'ep_ctx12#0x20': FIELD_RANDOM, 'ep_ctx13#0x20': FIELD_RANDOM, 'ep_ctx14#0x20': FIELD_RANDOM,
    'ep_ctx15#0x20': FIELD_RANDOM, 'ep_ctx16#0x20': FIELD_RANDOM, 'ep_ctx17#0x20': FIELD_RANDOM, 'ep_ctx18#0x20': FIELD_RANDOM, 'ep_ctx19#0x20': FIELD_RANDOM,
    'ep_ctx20#0x20': FIELD_RANDOM, 'ep_ctx21#0x20': FIELD_RANDOM, 'ep_ctx22#0x20': FIELD_RANDOM, 'ep_ctx23#0x20': FIELD_RANDOM, 'ep_ctx24#0x20': FIELD_RANDOM,
    'ep_ctx25#0x20': FIELD_RANDOM, 'ep_ctx26#0x20': FIELD_RANDOM, 'ep_ctx27#0x20': FIELD_RANDOM, 'ep_ctx28#0x20': FIELD_RANDOM, 'ep_ctx29#0x20': FIELD_RANDOM,
})
xhci_32.add_flag('ictrl_ctx12_1.ictrl_ctx0', {0: '2@3', 2: 30})
xhci_32.add_flag('ictrl_ctx12_1.ictrl_ctx1', {0: '2@3', 2: 30})
#xhci_evaluate_slot: 13
xhci_32.add_struct('ictrl_ctx13_1', {
    'ictrl_ctx0#0x4': FIELD_CONSTANT, 'ictrl_ctx1#0x4': FIELD_FLAG, 'reserved#0x24': FIELD_RANDOM,
    'islot_ctx#0x20': FIELD_RANDOM, 'ep0_ctx#0x20': FIELD_RANDOM
})
xhci_32.add_constant('ictrl_ctx13_1.ictrl_ctx0', 0)
xhci_32.add_flag('ictrl_ctx13_1.ictrl_ctx1', {0: 2, 2: '30@0'})
xhci_32.add_struct('XHCITRB_1', {'parameter#0x8': FIELD_POINTER, 'status#0x4': FIELD_FLAG, 'control#0x4': FIELD_FLAG, 'addr#0x8': FIELD_RANDOM, 'ccs#0x1': FIELD_RANDOM})
xhci_32.add_struct('XHCITRB1_1', {'parameter#0x8': FIELD_POINTER, 'status#0x4': FIELD_FLAG, 'control#0x4': FIELD_FLAG, 'addr#0x8': FIELD_RANDOM, 'ccs#0x1': FIELD_RANDOM})
xhci_32.add_flag('XHCITRB_1.control', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 2, 9: 1, 10: 6, 16: 5, 21: 3, 24: 8})
xhci_32.add_flag('XHCITRB_1.status', {0: 16, 16: 6, 22: 10})
xhci_32.add_flag('XHCITRB1_1.control', {0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 2, 9: 1, 10: 6, 16: 5, 21: 3, 24: 8})
xhci_32.add_flag('XHCITRB1_1.status', {0: 16, 16: 6, 22: 10})
xhci_32.add_context_flag_to_point_to(['XHCITRB1_1.control.10'], 'XHCITRB1_1.parameter', [
    None, None, None, None, None, None, None, None, None, None, None, 'ictrl_ctx11_1', 'ictrl_ctx12_1', 'ictrl_ctx13_1', None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
])
xhci_32.add_context_flag_to_point_to(['XHCITRB_1.control.10'], 'XHCITRB_1.parameter', [
    None, None, None, None, None, None, 'XHCITRB1_1', None, None, None, None, 'ictrl_ctx11_1', 'ictrl_ctx12_1', 'ictrl_ctx13_1', None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
])
# this is an array list: need more implementation
xhci_32.add_context_flag_to_point_to(None, 'XHCIEvRingSeg.addr', ['XHCITRB_1'])
xhci_32.add_head(['XHCIEvRingSeg'], ['xhci_er_reset', 'pci_dma_read'])
xhci_33 = Model('xhci', 33)
xhci_33.add_struct('poctx', {'poctx#0x8': FIELD_POINTER})
xhci_33.add_struct('slot_ctx', {'slot_ctx#0x40': FIELD_RANDOM})
xhci_33.add_context_flag_to_point_to(None, 'poctx.poctx', ['slot_ctx'])
xhci_33.add_head(['poctx'], ['xhci_address_slot', 'ldq_le_pci_dma'])
xhci_34 = Model('xhci', 34)
xhci_34.add_struct('ctx0', {'ctx0#0x4': FIELD_FLAG, 'ctx1#0x4': FIELD_RANDOM})
xhci_34.add_flag('ctx0.ctx0', {0: 1, 1: 3, 4: 28})
xhci_34.add_head(['ctx0'], ['xhci_find_stream', 'xhci_dma_read_u32s'])
xhci_35 = Model('xhci', 35)
xhci_35.add_struct('ctx1', {'ctx#0x12': FIELD_RANDOM})
xhci_35.add_head(['ctx1'], ['xhci_set_ep_state', 'xhci_dma_read_u32s'])
