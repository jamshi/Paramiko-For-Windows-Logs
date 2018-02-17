from server import Server
import unittest

class TestEncryption(unittest.TestCase):
    
    def test_encryptiondecryption(self):
        server = Server('jamsheedJAMSHEED')
        self.assertEqual(server.decrypt(server.encrypt("I Love this assignment")), "I Love this assignment")


if __name__ == "__main__":
    unittest.main()
