module Data.OpenPGP.Util.Fingerprint (fingerprint) where

import qualified Data.OpenPGP as OpenPGP
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LZ
import Data.Char (toUpper)
import Data.Word (Word8)
import Numeric (showHex)

import Crypto.Hash.MD5 as MD5
import Crypto.Hash.SHA1 as SHA1

-- | Generate a key fingerprint from a PublicKeyPacket or SecretKeyPacket
-- <http://tools.ietf.org/html/rfc4880#section-12.2>
fingerprint :: OpenPGP.Packet -> String
fingerprint p
    | OpenPGP.version p == 4 = hexify $ SHA1.hashlazy material
    | OpenPGP.version p `elem` [2, 3] = hexify $ MD5.hashlazy material
    | otherwise = error "Unsupported Packet version or type in fingerprint"
    where
    material = LZ.concat $ OpenPGP.fingerprint_material p

    hexify = map toUpper . hexString . BS.unpack

    hexString :: [Word8] -> String
    hexString = foldr (pad `oo` showHex) ""
        where
        pad s | odd $ length s = '0':s
              | otherwise = s

    oo :: (b -> c) -> (a -> a1 -> b) -> a -> a1 -> c
    oo = (.) . (.)

