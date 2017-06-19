{-# LANGUAGE CPP #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Common
where


import Data.Word (Word32 , Word16)
import Foreign.C.Types (CInt(..) , CSize(..))
import Data.List (genericLength)
import Foreign.Storable
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Marshal.Array (withArray)
import Foreign.C.String
    ( peekCString
    , withCStringLen
    )
import Foreign.C.Error
    ( throwErrnoIfMinus1
    , throwErrnoIfMinus1_
    )
import Foreign.Ptr
    ( Ptr
    , plusPtr -- in hsc2hs generated code
    , nullPtr
    , castPtr
    )
import Foreign.Marshal.Utils
    ( with
    , copyBytes
    , fillBytes
    )


#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif

afAlg :: Num a => a
afAlg = #{const AF_ALG}

solAlg :: Num a => a
solAlg = 279

algSetKey :: Num a => a
algSetKey = 1


data SockaddrAlg = SockaddrAlg
    { _salgType :: String
    , _salgFeat :: Word32
    , _salgMask :: Word32
    , _salgName :: String
    }
    deriving (Show, Eq)

#def struct sockaddr_alg {
        uint16_t salg_family;
        uint8_t  salg_type[14];
        uint32_t salg_feat;
        uint32_t salg_mask;
        uint8_t salg_name[64];
};

pokeCString :: String -> Ptr a -> IO ()
pokeCString str dst = withCStringLen str $ \(src, len) ->
    copyBytes dst (castPtr src) len

zero :: forall a. Storable a => Ptr a -> IO ()
zero ptr = fillBytes ptr 0 . fromIntegral $ sizeOf (undefined :: a)

instance Storable SockaddrAlg where
    sizeOf _ = #{size struct sockaddr_alg}
    alignment _ = #{alignment struct sockaddr_alg}
    peek ptr = SockaddrAlg
        <$> peekCString (#{ptr struct sockaddr_alg, salg_type} ptr)
        <*> #{peek struct sockaddr_alg, salg_feat} ptr
        <*> #{peek struct sockaddr_alg, salg_mask} ptr
        <*> peekCString (#{ptr struct sockaddr_alg, salg_name} ptr)
    poke ptr addr = do
        zero ptr
        #{poke struct sockaddr_alg, salg_family} ptr (afAlg :: Word16)
        pokeCString (_salgType addr) $ #{ptr struct sockaddr_alg, salg_type} ptr
        #{poke struct sockaddr_alg, salg_feat} ptr (_salgFeat addr)
        #{poke struct sockaddr_alg, salg_mask} ptr (_salgMask addr)
        pokeCString (_salgName addr) $ #{ptr struct sockaddr_alg, salg_name} ptr


data IOVec = IOVec (Ptr ()) CSize

instance Storable IOVec where
    sizeOf    _ = #{size struct iovec}
    alignment _ = #{alignment struct iovec}
    peek p = do
        addr <- #{peek struct iovec, iov_base} p
        len  <- #{peek struct iovec, iov_len}  p
        return $ IOVec addr len
    poke p (IOVec addr len) = do
        #{poke struct iovec, iov_base} p addr
        #{poke struct iovec, iov_len } p len

data CMsg a = CMsg
    { _cMsgLevel :: CInt
    , _cMsgType  :: CInt
    , _cMsgData  :: a
    }

data MsgHdr a b = MsgHdr
    { _msgName    :: Ptr a
    , _msgNameLen :: CSize
    , _msgIOVecs  :: [IOVec]
    , _msgControl :: Maybe (CMsg b)
    , _msgFlags   :: CInt
    }

withCMsg :: Storable a => Maybe (CMsg a) -> ((Ptr (CMsg a), CSize) -> IO b) -> IO b
withCMsg (Just cmsg) act =
    let size = #{size struct cmsghdr} + sizeOf (_cMsgData cmsg)
     in allocaBytes size $ \ptr -> do
         #{poke struct cmsghdr, cmsg_len} ptr (fromIntegral size :: CSize)
         #{poke struct cmsghdr, cmsg_type} ptr (_cMsgType cmsg)
         #{poke struct cmsghdr, cmsg_level} ptr (_cMsgLevel cmsg)
         #{poke struct cmsghdr, __cmsg_data} ptr (_cMsgData cmsg)
         act (ptr, fromIntegral size)
withCMsg Nothing act = act (nullPtr, 0)


withIOVecs :: [IOVec] -> ((Ptr IOVec, CSize) -> IO a) -> IO a
withIOVecs [] act = act (nullPtr, 0)
withIOVecs xs act = withArray xs $ \ ptr -> act (ptr, genericLength xs * #{size struct iovec})

withMsg :: Storable b => MsgHdr a b -> (Ptr (MsgHdr a b) -> IO c) -> IO c
withMsg msg act = allocaBytes #{size struct msghdr} $ \ptr -> do
    #{poke struct msghdr, msg_name} ptr $ _msgName msg
    #{poke struct msghdr, msg_namelen} ptr $ _msgNameLen msg
    #{poke struct msghdr, msg_flags} ptr $ _msgFlags msg
    withCMsg (_msgControl msg) $ \(cptr, clen) -> do
        #{poke struct msghdr, msg_control} ptr cptr
        #{poke struct msghdr, msg_controllen} ptr clen
        withIOVecs (_msgIOVecs msg) $ \(vptr, vlen) -> do
            #{poke struct msghdr, msg_iov} ptr vptr
            #{poke struct msghdr, msg_iovlen} ptr vlen
            act ptr

foreign import ccall "socket" c_socket :: CInt -> CInt -> CInt -> IO CInt
foreign import ccall "bind" c_bind :: CInt -> Ptr SockaddrAlg -> CSize -> IO CInt
foreign import ccall "close" c_close :: CInt -> IO ()
foreign import ccall "setsockopt" c_setsockopt :: CInt -> CInt -> CInt -> Ptr a -> CSize -> IO CInt
foreign import ccall "accept4" c_accept4 :: CInt -> Ptr a -> CSize -> CInt -> IO CInt
foreign import ccall "sendmsg" c_sendmsg :: CInt -> Ptr (MsgHdr a b) -> CInt -> IO CSize
foreign import ccall "read" c_read :: CInt -> Ptr a -> CSize -> IO CSize
foreign import ccall "send" c_send :: CInt -> Ptr a -> CSize -> CInt -> IO CSize

socket :: CInt -> CInt -> CInt -> IO CInt
socket fam flag prot = throwErrnoIfMinus1 "socket" $ c_socket fam flag prot

bind :: CInt -> SockaddrAlg -> IO ()
bind sock addr = with addr $ \ ptr ->
    throwErrnoIfMinus1_ "bind" $ c_bind sock ptr (fromIntegral $ sizeOf addr)

close :: CInt -> IO ()
close = c_close

accept4 :: CInt -> Ptr a -> CSize -> CInt -> IO CInt
accept4 sock addr size flags = throwErrnoIfMinus1 "accept4" $
    c_accept4 sock addr size flags

setSockopt' :: CInt -> CInt -> CInt -> Ptr a -> CSize -> IO ()
setSockopt' sock level name ptr size = 
    throwErrnoIfMinus1_ ("setsockopt:" ++ show level ++ ':' : show name) $
        c_setsockopt sock level name ptr size

sendMsg :: Storable b => CInt -> MsgHdr a b -> CInt -> IO CSize
sendMsg sock hdr flags = withMsg hdr $ \ptr ->
    throwErrnoIfMinus1 "sendmsg" $ c_sendmsg sock ptr flags

read :: CInt -> Ptr a -> CSize -> IO CSize
read sock dst size = throwErrnoIfMinus1 "read" $ c_read sock dst size

send :: CInt -> Ptr a -> CSize -> CInt -> IO ()
send sock src size flags = throwErrnoIfMinus1_ "send" $ c_send sock src size flags

-- setSockopt :: Storable a => CInt -> CInt -> CInt -> a -> IO ()
-- setSockopt sock level name val = with val $ \ptr -> 
--     setSockopt' sock level name ptr (fromIntegral $ sizeOf val)

-- setSockoptBS :: CInt -> CInt -> CInt -> ByteString -> IO ()
-- setSockoptBS sock level name bs = BS.unsafeUseAsCStringLen bs $ \(ptr, size) ->
--     setSockopt' sock level name ptr (fromIntegral size)
--
