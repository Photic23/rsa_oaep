import unittest
import custom_sha256

test_vector_1 = ""
test_vector_2 = "abc"
test_vector_3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
test_vector_4 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
test_vector_5 = "a" * 1000000
test_vector_6 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqp" #edge-case: between 448 and 512 bits long message (456)
test_vector_7 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqpqpmomom" #edge-case: 512 bits
test_vector_8 = "ibsnqwpzhillptcinmtvamymvixjxaumjddwxsxxjhjhnftynajhsluuctgjytazlcdewsexbjcpumdcfbbbmzwxcmjmnxfqurvaarapdswyatlyvqsxdefmehicwwdnkshzgysaxxenmtpirbhphxyaesgwigdxzqpekouenexqkqgpnzzwyjppc"
sha_1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
sha_2 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
sha_3 = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
sha_4 = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
sha_5 = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
sha_6 = "3234a5b08b1112a6cb90bf9920ca1863535c9380a65633e5442befda64f84a6f" #hashlib result
sha_7 = "19c638400f16d98b8d955a0bfe853cb11c33a987389ac2311b9c0ba2cd1efa34" #hashlib result
sha_8 = '6540979c2b56a3f4b17dada9a3d1fba7161d0e10f2c2d87b0b6486377bf88ecc'

class TestSHA256(unittest.TestCase):
    def test_sha256(self):
        """tes apakah custom_sha256 hash dengan benar sesuai dengan hashlib"""
        r_1 = custom_sha256.new(test_vector_1).hexdigest()
        r_2 = custom_sha256.new(test_vector_2).hexdigest()
        r_3 = custom_sha256.new(test_vector_3).hexdigest()
        r_4 = custom_sha256.new(test_vector_4).hexdigest()
        r_5 = custom_sha256.new(test_vector_5).hexdigest()
        r_6 = custom_sha256.new(test_vector_6).hexdigest()
        r_7 = custom_sha256.new(test_vector_7).hexdigest()
        r_8 = custom_sha256.new(test_vector_8).hexdigest()
        self.assertEqual(r_1, sha_1)
        self.assertEqual(r_2, sha_2)
        self.assertEqual(r_3, sha_3)
        self.assertEqual(r_4, sha_4)
        self.assertEqual(r_5, sha_5)
        self.assertEqual(r_6, sha_6)
        self.assertEqual(r_7, sha_7)
        self.assertEqual(r_8, sha_8)

if __name__ == '__main__':
    unittest.main()



