module Data.OpenPGP.Util.Base where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LZ
import Data.Binary (encode)

import Data.OpenPGP as OpenPGP
import Crypto.Hash.MD5 as MD5
import Crypto.Hash.SHA1 as SHA1
import Crypto.Hash.SHA256 as SHA256
import Crypto.Hash.SHA384 as SHA384
import Crypto.Hash.SHA512 as SHA512
import Crypto.Hash.SHA224 as SHA224
import Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Crypto.PubKey.RSA as Vincent.RSA
import Crypto.PubKey.HashDescr as Vincent
import qualified Crypto.Types.PubKey.ECC as Vincent.ECDSA
import qualified Crypto.Types.PubKey.ECDSA as Vincent.ECDSA

import Data.OpenPGP.Util.Fingerprint (fingerprint)

hashBySymbol OpenPGP.MD5 = MD5.hashlazy
hashBySymbol OpenPGP.SHA1 = SHA1.hashlazy
hashBySymbol OpenPGP.SHA256 = SHA256.hashlazy
hashBySymbol OpenPGP.SHA384 = SHA384.hashlazy
hashBySymbol OpenPGP.SHA512 = SHA512.hashlazy
hashBySymbol OpenPGP.SHA224 = SHA224.hashlazy
hashBySymbol OpenPGP.RIPEMD160 = RIPEMD160.hashlazy

curveFromOID :: Integer -> Vincent.ECDSA.Curve
curveFromOID 0x2a8648ce3d030107 = Vincent.ECDSA.getCurveByName Vincent.ECDSA.SEC_p256r1 -- NIST P-256
curveFromOID 0x2B81040022       = Vincent.ECDSA.getCurveByName Vincent.ECDSA.SEC_p384r1 -- NIST P-384
curveFromOID 0x2B81040023       = Vincent.ECDSA.getCurveByName Vincent.ECDSA.SEC_p521r1 -- NIST P-521
curveFromOID 0x2b8104000a       = Vincent.ECDSA.getCurveByName Vincent.ECDSA.SEC_p256k1 -- bitcoin curve
curveFromOID n = error $ "Unknown curve: "++ show n

ecdsaKey k = Vincent.ECDSA.PublicKey curve (Vincent.ECDSA.Point x y)
 where
    x = keyParam 'x' k
    y = keyParam 'y' k
    curve = curveFromOID (keyParam 'c' k)


toStrictBS :: LZ.ByteString -> BS.ByteString
toStrictBS = BS.concat . LZ.toChunks

toLazyBS :: BS.ByteString -> LZ.ByteString
toLazyBS = LZ.fromChunks . (:[])

find_key :: OpenPGP.Message -> String -> Maybe OpenPGP.Packet
find_key = OpenPGP.find_key fingerprint



keyParam :: Char -> OpenPGP.Packet -> Integer
keyParam c k = fromJustMPI $ lookup c (OpenPGP.key k)
 where
    fromJustMPI :: Maybe OpenPGP.MPI -> Integer
    fromJustMPI (Just (OpenPGP.MPI x)) = x
    fromJustMPI _ = error "Not a Just MPI, Data.OpenPGP.CryptoAPI"

integerBytesize :: Integer -> Int
integerBytesize i = fromIntegral $ LZ.length (encode (OpenPGP.MPI i)) - 2

rsaKey :: OpenPGP.Packet -> Vincent.RSA.PublicKey
rsaKey k =
    Vincent.RSA.PublicKey (integerBytesize n) n (keyParam 'e' k)
    where
    n = keyParam 'n' k

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


