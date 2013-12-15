module Data.OpenPGP.Util.Verify where

import qualified Data.OpenPGP as OpenPGP
import Data.Maybe
import Data.Binary (encode)
import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LZ
import Data.Monoid ( (<>) )

import Data.OpenPGP.Util.Fingerprint (fingerprint)

import qualified Crypto.PubKey.DSA as Vincent.DSA
import qualified Crypto.PubKey.RSA as Vincent.RSA
import qualified Crypto.PubKey.RSA.PKCS15 as Vincent.RSA
import Crypto.PubKey.HashDescr as Vincent

import Crypto.Hash.MD5 as MD5
import Crypto.Hash.SHA1 as SHA1
import Crypto.Hash.SHA256 as SHA256
import Crypto.Hash.SHA384 as SHA384
import Crypto.Hash.SHA512 as SHA512
import Crypto.Hash.SHA224 as SHA224
import Crypto.Hash.RIPEMD160 as RIPEMD160

hashBySymbol OpenPGP.MD5 = MD5.hashlazy
hashBySymbol OpenPGP.SHA1 = SHA1.hashlazy
hashBySymbol OpenPGP.SHA256 = SHA256.hashlazy
hashBySymbol OpenPGP.SHA384 = SHA384.hashlazy
hashBySymbol OpenPGP.SHA512 = SHA512.hashlazy
hashBySymbol OpenPGP.SHA224 = SHA224.hashlazy
hashBySymbol OpenPGP.RIPEMD160 = RIPEMD160.hashlazy


toStrictBS :: LZ.ByteString -> BS.ByteString
toStrictBS = BS.concat . LZ.toChunks

toLazyBS :: BS.ByteString -> LZ.ByteString
toLazyBS = LZ.fromChunks . (:[])

hush :: Either a b -> Maybe b
hush (Left _) = Nothing
hush (Right x) = Just x

fromJustMPI :: Maybe OpenPGP.MPI -> Integer
fromJustMPI (Just (OpenPGP.MPI x)) = x
fromJustMPI _ = error "Not a Just MPI, Data.OpenPGP.CryptoAPI"



find_key :: OpenPGP.Message -> String -> Maybe OpenPGP.Packet
find_key = OpenPGP.find_key fingerprint

integerBytesize :: Integer -> Int
integerBytesize i = fromIntegral $ LZ.length (encode (OpenPGP.MPI i)) - 2

dsaKey :: OpenPGP.Packet -> Vincent.DSA.PublicKey
dsaKey k = Vincent.DSA.PublicKey
    (Vincent.DSA.Params (keyParam 'p' k) (keyParam 'g' k) (keyParam 'q' k))
    (keyParam 'y' k)

rsaKey :: OpenPGP.Packet -> Vincent.RSA.PublicKey
rsaKey k =
    Vincent.RSA.PublicKey (integerBytesize n) n (keyParam 'e' k)
    where
    n = keyParam 'n' k


keyParam :: Char -> OpenPGP.Packet -> Integer
keyParam c k = fromJustMPI $ lookup c (OpenPGP.key k)


-- | Verify a message signature
verify ::
    OpenPGP.Message          -- ^ Keys that may have made the signature
    -> OpenPGP.SignatureOver -- ^ Signatures to verify
    -> OpenPGP.SignatureOver -- ^ Will only contain signatures that passed
verify keys over =
    over {OpenPGP.signatures_over = mapMaybe (uncurry $ verifyOne keys) sigs}
    where
    sigs = map (\s -> (s, toStrictBS $ encode over `LZ.append` OpenPGP.trailer s))
        (OpenPGP.signatures_over over)

verifyOne :: OpenPGP.Message -> OpenPGP.Packet -> BS.ByteString -> Maybe OpenPGP.Packet
verifyOne keys sig over = fmap (const sig) $ maybeKey >>= verification >>= guard
    where
    verification = case OpenPGP.key_algorithm sig of
        OpenPGP.DSA -> dsaVerify
        alg | alg `elem` [OpenPGP.RSA,OpenPGP.RSA_S] -> rsaVerify
            | otherwise -> const Nothing
    dsaVerify k = let k' = dsaKey k in 
        Just $ Vincent.DSA.verify (dsaTruncate k' . bhash) k' dsaSig over
    rsaVerify k = Just $ Vincent.RSA.verify desc (rsaKey k) over rsaSig
    [rsaSig] = map (toStrictBS . LZ.drop 2 . encode) (OpenPGP.signature sig)
    dsaSig = let [OpenPGP.MPI r, OpenPGP.MPI s] = OpenPGP.signature sig in
        Vincent.DSA.Signature r s
    dsaTruncate (Vincent.DSA.PublicKey (Vincent.DSA.Params _ _ q) _) = BS.take (integerBytesize q)
    bhash = hashBySymbol hash_algo . toLazyBS
    desc = hashAlgoDesc hash_algo
    hash_algo = OpenPGP.hash_algorithm sig
    maybeKey = OpenPGP.signature_issuer sig >>= find_key keys

-- http://tools.ietf.org/html/rfc3447#page-43
-- http://tools.ietf.org/html/rfc4880#section-5.2.2
hashAlgoDesc OpenPGP.MD5       = Vincent.hashDescrMD5
hashAlgoDesc OpenPGP.SHA1      = Vincent.hashDescrSHA1
hashAlgoDesc OpenPGP.RIPEMD160 = Vincent.hashDescrRIPEMD160
hashAlgoDesc OpenPGP.SHA256    = Vincent.hashDescrSHA256
hashAlgoDesc OpenPGP.SHA384    = Vincent.hashDescrSHA384
hashAlgoDesc OpenPGP.SHA512    = Vincent.hashDescrSHA512
hashAlgoDesc OpenPGP.SHA224    = Vincent.hashDescrSHA224
hashAlgoDesc _ =
       error "Unsupported HashAlgorithm in hashAlgoDesc"


