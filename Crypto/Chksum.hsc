-- {-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Chksum
    ( createUnkeyed
    , createKeyed
    , createKeyedBS
    , Chksum
    , freeChksum
    , updateChksum
    , updateChksumBS
    , digestChksum
    , digestChksumBS
    , unkeyedHashBS
    , unkeyedHash
    )
where

import Control.Monad (void)
import Crypto.Common
import Crypto.Hash
import Data.Bits ((.|.))
import Data.ByteString (ByteString)
import Foreign.C.Types (CSize, CInt)
import Foreign.Ptr (Ptr, nullPtr)
import Prelude hiding (read)
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.ByteString.Internal as BS (create)
import qualified Data.ByteString.Unsafe as BS (unsafeUseAsCStringLen)

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

newtype Chksum a = Chksum { _chkSock :: CInt }

createAlg :: forall a b. Hash a => Maybe (Ptr b, CSize) -> IO (Chksum a)
createAlg mkey = do
    let flags = #{const SOCK_SEQPACKET} .|. #{const SOCK_CLOEXEC}
    sock <- socket afAlg flags 0
    let addr = SockaddrAlg "hash" 0 0 $ algName (undefined :: a)
    bind sock addr
    case mkey of
        Just (key, size) -> setSockopt' sock solAlg algSetKey key size
        Nothing -> pure ()
    ret <- accept4 sock nullPtr 0 #{const SOCK_CLOEXEC}
    print ret
    close sock
    pure $ Chksum ret

createUnkeyed :: Unkeyed a => IO (Chksum a)
createUnkeyed = createAlg Nothing

createKeyed :: Keyed a => Ptr b -> CSize -> IO (Chksum a)
createKeyed ptr size = createAlg $ Just (ptr, size)

createKeyedBS :: Keyed a => ByteString -> IO (Chksum a)
createKeyedBS bs =
    BS.unsafeUseAsCStringLen bs $ createAlg . Just . fmap fromIntegral

freeChksum :: Chksum a -> IO ()
freeChksum (Chksum s) = close s

updateChksum :: Chksum a -> Ptr b -> CSize -> IO ()
updateChksum (Chksum s) ptr size =
    send s ptr size #{const MSG_MORE}

updateChksumBS :: Chksum a -> ByteString -> IO ()
updateChksumBS chk bs =
    BS.unsafeUseAsCStringLen bs $ uncurry (updateChksum chk) . fmap fromIntegral

digestChksum :: Chksum a -> Ptr b -> CSize -> IO CSize
digestChksum (Chksum s) ptr size = read s ptr size

digestChksumBS :: forall a. Hash a => Chksum a -> IO ByteString
digestChksumBS chk =
    let len = outSize (undefined :: a)
     in BS.create (fromIntegral len) $ \ptr ->
        void $ digestChksum chk ptr (fromIntegral len)

unkeyedHash :: forall a b c. Unkeyed a => a -> Ptr b -> CSize -> Ptr c -> CSize -> IO ()
unkeyedHash _ iPtr iSize oPtr oSize = do
    chk :: Chksum a <- createUnkeyed
    updateChksum chk iPtr iSize
    _ <- digestChksum chk oPtr oSize
    freeChksum chk

unkeyedHashBS' :: forall a. Unkeyed a => a -> ByteString -> IO ByteString
unkeyedHashBS' _ bs = do
    chk :: Chksum a <- createUnkeyed
    updateChksumBS chk bs
    ret <- digestChksumBS chk
    freeChksum chk
    pure ret

unkeyedHashBS :: Unkeyed a => a -> ByteString -> ByteString
unkeyedHashBS chk bs = unsafePerformIO $ unkeyedHashBS' chk bs
{-# NOINLINE unkeyedHashBS #-}
