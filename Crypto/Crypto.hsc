{-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Crypto
    ( Crypt
    , createCipher
    , createCipherBS
    , encrypt
    , encryptBS
    , encryptPaddedBS
    , decrypt
    , decryptBS
    , decryptPaddedBS
    )
where

import Crypto.Common
import Crypto.Cipher
import Prelude hiding (read)
import Control.Monad (void, when)
import Data.Bits ((.|.), (.&.), complement)
import Foreign.C.Types (CInt(..) , CSize(..))
import Foreign.Marshal.Utils
    ( copyBytes
    , fillBytes
    )
import Data.Word (Word32)
import Foreign.Storable
import Foreign.Marshal.Alloc (allocaBytes)

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
    ( length
    , last
    , take
    , drop
    , unpack
    )
import qualified Data.ByteString.Unsafe as BS (unsafeUseAsCStringLen)
import qualified Data.ByteString.Internal as BS (create)

import Foreign.Ptr
    ( Ptr
    , plusPtr -- in hsc2hs generated code
    , nullPtr
    , castPtr
    )

data Crypt a = Crypt
    { _cryptDeSock :: CInt
    , _cryptEnSock :: CInt
    }

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

algSetIV :: Num a => a
algSetIV = 2

algSetOp :: Num a => a
algSetOp = 3

algSetPubkey :: Num a => a
algSetPubkey = 6

algOpDecrypt :: Num a => a
algOpDecrypt = 0

algOpEncrypt :: Num a => a
algOpEncrypt = 1

newtype Key a = Key (Ptr a)

getKey :: forall a b. Cipher b => Ptr a -> CSize -> Key b
getKey ptr size =
    if keySize (undefined :: b) /= size * 8
            then error "Got a key of the wrong size"
            else  Key $ castPtr ptr

createAlg :: String -> String -> Ptr a -> CSize -> Bool -> IO CInt
createAlg aType aName key size pub = do
    let flags = #{const SOCK_SEQPACKET} .|. #{const SOCK_CLOEXEC}
    sock <- socket afAlg flags 0
    let addr = SockaddrAlg aType 0 0 aName
    bind sock addr
    let opt = if pub then algSetPubkey else algSetKey
    setSockopt' sock solAlg opt key size
    ret <- accept4 sock nullPtr 0 #{const SOCK_CLOEXEC}
    close sock
    pure ret

newtype IV = IV ByteString

instance Storable IV where
    sizeOf (IV bs) = 4 + BS.length bs
    alignment _ = 4
    poke ptr (IV bs) = do
        poke (castPtr ptr) (fromIntegral $ BS.length bs :: Word32)
        BS.unsafeUseAsCStringLen bs $ \(bptr, len) ->
            copyBytes (castPtr $ plusPtr ptr 4) bptr len
    peek _ = undefined

setIV :: forall a. IVCipher a => Crypt a -> ByteString -> IO ()
setIV (Crypt enc dec) iv = do
    let size = fromIntegral $ ivSize (undefined :: a)
    when (BS.length iv * 8 /= size) $ error "Wrong size IV"
    let cmsg = CMsg solAlg algSetIV $ IV iv
    let msg = MsgHdr nullPtr 0 [] (Just cmsg) 0
    void $ sendMsg enc msg 0
    void $ sendMsg dec msg 0

createCipher :: forall b. Cipher b => Key b -> IO (Crypt b)
createCipher (Key ptr) = let x :: b = undefined in Crypt
    <$> createAlg "skcipher" (cipherName x) ptr (keySize x `div` 8) False
    <*> createAlg "skcipher" (cipherName x) ptr (keySize x `div` 8) False

createCipherBS :: IVCipher a => ByteString -> ByteString -> IO (Crypt a)
createCipherBS key iv = BS.unsafeUseAsCStringLen key $ \ (ptr, size) -> do
    crypt <- createCipher $ getKey ptr (fromIntegral size)
    setIV crypt iv
    return crypt

operateCipher' :: CInt -> Word32 -> [IOVec] -> Ptr b -> CSize -> IO CSize
operateCipher' sock opt src dst size = do
    let cmsg :: CMsg Word32 = CMsg solAlg algSetOp opt
    let msghdr = MsgHdr nullPtr 0 src (Just cmsg) 0
    _ <- sendMsg sock msghdr 0
    read sock dst size

operateCipher :: CInt -> Word32 -> Ptr a -> Ptr b -> CSize -> CSize -> IO CSize
operateCipher sock opt src dst srcsize dstsize =
    operateCipher' sock opt [IOVec (castPtr src) srcsize] dst dstsize

encrypt :: Crypt a -> Ptr b -> CSize -> IO ByteString
encrypt (Crypt _ sock) src size = do
    BS.create (fromIntegral size) $ \dst ->
        void $ operateCipher sock algOpEncrypt src dst size size

decrypt :: Crypt a -> ByteString -> Ptr b -> CSize -> IO ()
decrypt (Crypt sock _) bs dst dsize = void $
    BS.unsafeUseAsCStringLen bs $ \(src, ssize) ->
        operateCipher sock algOpDecrypt src dst (fromIntegral ssize) dsize


encryptBS :: Crypt a -> ByteString -> IO ByteString
encryptBS c bs = BS.unsafeUseAsCStringLen bs $ \(ptr, len) ->
    encrypt c ptr (fromIntegral len)

decryptBS :: Crypt a -> ByteString -> IO ByteString
decryptBS c bs =
    let len = BS.length bs
     in BS.create len $ \dst ->
         decrypt c bs dst (fromIntegral len)

align :: CSize -> CSize -> CSize
align x y = (x + y - 1) .&. complement (y - 1)

encryptPaddedBS :: forall a . BlockCipher a => Crypt a -> ByteString -> IO ByteString
encryptPaddedBS (Crypt _ sock) bs =
    let bSize = blockSize (undefined :: a) `div` 8
        tSize = fromIntegral $ BS.length bs
        total = align (tSize + 1) bSize
        diff  = fromIntegral $ total - tSize
     in allocaBytes diff $ \padding -> do
        fillBytes padding (fromIntegral diff) diff
        let padIOV = IOVec padding (fromIntegral diff)
        BS.unsafeUseAsCStringLen bs $ \(ptr, _) ->
            let textIOV = IOVec (castPtr ptr) tSize
             in BS.create (fromIntegral total) $ \dst ->
                void $ operateCipher' sock algOpEncrypt [textIOV, padIOV] dst total

decryptPaddedBS :: forall a . BlockCipher a => Crypt a -> ByteString -> IO ByteString
decryptPaddedBS crypt enc = do
    dec <- decryptBS crypt enc
    let padS = BS.last dec
    let size = BS.length dec - fromIntegral padS
    when (size < 0) $ error "Padding was longer than decrypted BS"
    let ret = BS.take size dec
    let pad = BS.drop size dec
    when (any (/= padS) $ BS.unpack pad) $ error "Padding wasn't all padding"
    return ret


