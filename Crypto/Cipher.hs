{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE EmptyDataDecls #-}
module Crypto.Cipher
where

import Foreign.C.Types (CSize)


class Cipher a where
    keySize :: a -> CSize
    cipherName :: a -> String

class Cipher a => PrimCipher a

class Cipher a => BlockCipher a where
    blockSize :: a -> CSize

data AES

instance Cipher AES where
    keySize _ = 128
    cipherName _ = "aes"

instance BlockCipher AES where
    blockSize _ = 128

instance PrimCipher AES

class Cipher a => IVCipher a where
    ivSize :: a -> CSize

data CBC a

instance (PrimCipher a, Cipher a) => Cipher (CBC a) where
    keySize _ = keySize (undefined :: a)
    cipherName _ = "cbc(" ++ cipherName (undefined :: a) ++ ")"

instance (PrimCipher a, BlockCipher a) => BlockCipher (CBC a) where
    blockSize _ = blockSize (undefined :: a)

instance (PrimCipher a, BlockCipher a) => IVCipher (CBC a) where
    ivSize _ = blockSize (undefined :: a)

