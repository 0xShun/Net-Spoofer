import unittest
from arp_spoof import ARP_SPOOFING
from unittest.mock import patch

class TestARPSpoofing(unittest.TestCase):
    def setUp(self):
        # Setup code to initialize ARP_SPOOFING with test data
        self.arp_spoofing = ARP_SPOOFING(victim_ip='192.168.1.10', router_ip='192.168.1.1')

    @patch('arp_spoof.ARP_SPOOFING.get_mac')
    @patch('arp_spoof.scapy.send')
    def test_arp_spoof(self, mock_send, mock_get_mac):
        # Mock the get_mac method to return a valid MAC address
        mock_get_mac.return_value = '00:11:22:33:44:55'
        # Test the arp_spoof method
        try:
            self.arp_spoofing.arp_spoof(self.arp_spoofing.victim_ip, self.arp_spoofing.router_ip)
            mock_send.assert_called()  # Check if scapy.send was called
            self.assertTrue(True)
        except Exception as e:
            self.fail(f"arp_spoof method failed with exception: {e}")

if __name__ == '__main__':
    unittest.main() 