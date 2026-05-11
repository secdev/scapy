from __future__ import annotations

import unittest

from packet_studio.services.packet_builder_service import PacketBuilderService


class PacketBuilderServiceImportTests(unittest.TestCase):
    def test_list_available_layers_includes_additional_scapy_protocols(self) -> None:
        service = PacketBuilderService()

        availableLayerNames = {layer.packetClassName for layer in service.listAvailableLayers()}

        self.assertIn("LLC", availableLayerNames)
        self.assertIn("STP", availableLayerNames)
        self.assertIn("BOOTP", availableLayerNames)

    def test_dynamic_layer_labels_do_not_use_packet_name_descriptor_repr(self) -> None:
        service = PacketBuilderService()

        dhcp6ReplyLayer = next(
            layer for layer in service.listAvailableLayers() if layer.packetClassName == "DHCP6_Reply"
        )

        self.assertEqual(dhcp6ReplyLayer.label, "DHCP6_Reply")
        self.assertNotIn("<member 'name'", dhcp6ReplyLayer.label)

    def test_import_packet_splits_supported_layers(self) -> None:
        service = PacketBuilderService()
        import scapy.all as scapy

        packet = scapy.IP(dst="1.1.1.1") / scapy.ICMP() / scapy.Raw(load=b"abc")

        service.importPacket(packet)

        layerRecords = service.getLayerRecords()
        self.assertEqual([record.name for record in layerRecords], ["IP", "ICMP", "Raw"])
        rebuiltPacket = service.buildPacket()
        self.assertIsNotNone(rebuiltPacket)
        self.assertEqual(bytes(rebuiltPacket), bytes(packet))

    def test_ether_type_field_uses_hex_and_contains_common_choices(self) -> None:
        service = PacketBuilderService()
        service.addLayer("ether")

        fieldRecords = service.getFieldRecords(0)
        typeField = next(record for record in fieldRecords if record.name == "type")

        self.assertEqual(typeField.currentValue, "0x9000")
        self.assertIn(("0x0800", "IPv4 (0x0800)"), typeField.choices)
        self.assertIn(("0x8808", "Ethernet PAUSE (0x8808)"), typeField.choices)

    def test_ether_type_field_accepts_custom_hex_value(self) -> None:
        service = PacketBuilderService()
        service.addLayer("ether")

        service.setFieldValue(0, "type", "0x8808")

        self.assertEqual(service.getFieldNativeValue(0, "type"), 0x8808)
        self.assertEqual(service.getFieldValue(0, "type"), "0x8808")

    def test_import_packet_skips_abstract_mac_control_wrapper(self) -> None:
        service = PacketBuilderService()
        import scapy.all as scapy
        from scapy.contrib.mac_control import MACControlPause

        packet = scapy.Ether(bytes(scapy.Ether(type=0x8808) / MACControlPause(pause_time=3)))

        service.importPacket(packet)

        layerRecords = service.getLayerRecords()
        self.assertEqual(
            [record.name for record in layerRecords],
            ["Ethernet", "MACControlPause", "Raw"],
        )
        rebuiltPacket = service.buildPacket()
        self.assertIsNotNone(rebuiltPacket)
        self.assertEqual(bytes(rebuiltPacket), bytes(packet))

    def test_import_packet_supports_previously_missing_llc_and_stp_layers(self) -> None:
        service = PacketBuilderService()
        import scapy.all as scapy

        packet = scapy.Ether() / scapy.LLC() / scapy.STP()

        service.importPacket(packet)

        layerRecords = service.getLayerRecords()
        self.assertEqual(
            [record.name for record in layerRecords],
            ["Ethernet", "LLC", "Spanning Tree Protocol"],
        )
        rebuiltPacket = service.buildPacket()
        self.assertIsNotNone(rebuiltPacket)
        self.assertEqual(bytes(rebuiltPacket), bytes(packet))


if __name__ == "__main__":
    unittest.main()