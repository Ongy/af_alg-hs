{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE EmptyDataDecls #-}
module Crypto.Hash
where


class Hash a where
    outSize :: a -> Word
    algName :: a -> String

class Hash a => Unkeyed a

class Hash a => Keyed a

data SHA256

instance Hash SHA256 where
    outSize _ = 256
    algName _ = "sha256"

instance Unkeyed SHA256

data HMAC a

instance Unkeyed a => Hash (HMAC a) where
    outSize _ = outSize (undefined :: a)
    algName _ = "hmac(" ++ algName (undefined :: a) ++ ")"

instance Unkeyed a => Keyed (HMAC a)
