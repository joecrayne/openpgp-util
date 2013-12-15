module Data.OpenPGP.Util.DecryptSecretKey where

import qualified Data.OpenPGP as OpenPGP
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LZ
import Data.Word (Word16)
import Control.Monad (foldM)
import Data.Binary (get,Binary,Get)
import Data.Binary.Get (runGetOrFail)
import qualified Data.Serialize as Serialize
import Control.Applicative ( (<$>) )

import Crypto.Hash.SHA1 as SHA1

import qualified Crypto.Cipher.AES as Vincent
import qualified Crypto.Cipher.Blowfish as Vincent

import qualified Crypto.Cipher.Types as Vincent
import qualified Data.Byteable as Vincent

import Crypto.Cipher.Cast5 (CAST5_128)
import Crypto.Cipher.ThomasToVincent
import Data.OpenPGP.Util.Base (toStrictBS,toLazyBS,hashBySymbol)




data Enciphered = 
         EncipheredWithIV !LZ.ByteString -- initial vector is appended to front of ByteString
       | EncipheredZeroIV !LZ.ByteString -- initial vector is zero, ByteString contains only the block

withIV :: (Vincent.BlockCipher k) => (Vincent.IV k -> LZ.ByteString -> LZ.ByteString) -> Enciphered -> LZ.ByteString
withIV f (EncipheredWithIV s) = f iv bs
    where
    Just iv = Vincent.makeIV (toStrictBS ivbs)
    (ivbs,bs) = LZ.splitAt (fromIntegral ivlen) s
    ivlen = Vincent.byteableLength z
    z = Vincent.nullIV
    _ = Vincent.constEqBytes z iv
withIV f (EncipheredZeroIV s) = f Vincent.nullIV s

decryptSecretKey ::
    BS.ByteString           -- ^ Passphrase
    -> OpenPGP.Packet       -- ^ Encrypted SecretKeyPacket
    -> Maybe OpenPGP.Packet -- ^ Decrypted SecretKeyPacket
decryptSecretKey pass k@(OpenPGP.SecretKeyPacket {
        OpenPGP.version = 4, OpenPGP.key_algorithm = kalgo,
        OpenPGP.s2k = s2k, OpenPGP.symmetric_algorithm = salgo,
        OpenPGP.key = existing, OpenPGP.encrypted_data = encd
    }) | chkF material == toStrictBS chk =
        fmap (\m -> k {
            OpenPGP.s2k_useage = 0,
            OpenPGP.symmetric_algorithm = OpenPGP.Unencrypted,
            OpenPGP.encrypted_data = LZ.empty,
            OpenPGP.key = m
        }) parseMaterial
       | otherwise = Nothing
    where
    parseMaterial = maybeGet
        (foldM (\m f -> do {mpi <- get; return $ (f,mpi):m}) existing
        (OpenPGP.secret_key_fields kalgo)) material
    (material, chk) = LZ.splitAt (LZ.length decd - chkSize) decd
    (chkSize, chkF)
        | OpenPGP.s2k_useage k == 254 = (20, SHA1.hash . toStrictBS)
        | otherwise = (2, Serialize.encode . checksum . toStrictBS)
    decd = string2sdecrypt salgo s2k (toLazyBS pass) (EncipheredWithIV encd)

    checksum :: BS.ByteString -> Word16
    checksum key = fromIntegral $
        BS.foldl' (\x y -> x + fromIntegral y) (0::Integer) key `mod` 65536

    maybeGet :: (Binary a) => Get a -> LZ.ByteString -> Maybe a
    maybeGet g bs = (\(_,_,x) -> x) <$> hush (runGetOrFail g bs)

    hush :: Either a b -> Maybe b
    hush (Left _) = Nothing
    hush (Right x) = Just x


decryptSecretKey _ _ = Nothing


string2sdecrypt :: OpenPGP.SymmetricAlgorithm -> OpenPGP.S2K -> LZ.ByteString -> Enciphered -> LZ.ByteString
string2sdecrypt OpenPGP.AES128 s2k s = withIV $ simpleUnCFB (string2key s2k s :: Vincent.AES128)
string2sdecrypt OpenPGP.AES192 s2k s = withIV $ simpleUnCFB (string2key s2k s :: Vincent.AES192)
string2sdecrypt OpenPGP.AES256 s2k s = withIV $ simpleUnCFB (string2key s2k s :: Vincent.AES256)
string2sdecrypt OpenPGP.Blowfish s2k s = withIV $ simpleUnCFB (string2key s2k s :: Vincent.Blowfish128)
string2sdecrypt OpenPGP.CAST5 s2k s = withIV $ simpleUnCFB (string2key s2k s :: ThomasToVincent CAST5_128)
string2sdecrypt algo _ _ = error $ "Unsupported symmetric algorithm : " ++ show algo ++ " in Data.OpenPGP.CryptoAPI.string2sdecrypt"

simpleUnCFB :: (Vincent.BlockCipher k) => k -> Vincent.IV k -> LZ.ByteString -> LZ.ByteString
simpleUnCFB k iv = padThenUnpad k (toLazyBS . Vincent.cfbDecrypt k iv . toStrictBS)
    where
    padThenUnpad :: (Vincent.BlockCipher k) => k -> (LZ.ByteString -> LZ.ByteString) -> LZ.ByteString -> LZ.ByteString
    padThenUnpad k f s = dropPadEnd (f padded)
        where
        dropPadEnd s = LZ.take (LZ.length s - padAmount) s
        padded = s `LZ.append` LZ.replicate padAmount 0
        padAmount = blksize - (LZ.length s `mod` blksize)
        blksize = fromIntegral $ Vincent.blockSize k

string2key :: (Vincent.BlockCipher k) => OpenPGP.S2K -> LZ.ByteString -> k
string2key s2k s = cipher
    where
    cipher = Vincent.cipherInit k
    Right k = Vincent.makeKey $ toStrictBS $
        LZ.take ksize $ OpenPGP.string2key hashBySymbol s2k s
    ksize = case Vincent.cipherKeySize cipher of
                Vincent.KeySizeFixed n -> fromIntegral n
                Vincent.KeySizeEnum xs -> error $ "Unknown key size in string2key"
                Vincent.KeySizeRange min max -> error $ "Unknown key size range in string2key"

