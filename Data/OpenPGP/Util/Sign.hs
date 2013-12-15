{-# LANGUAGE ScopedTypeVariables #-}
module Data.OpenPGP.Util.Sign where

import qualified Data.OpenPGP as OpenPGP
import Data.Maybe
import Data.Binary (encode)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LZ
import Data.Bits ( (.|.), shiftL )
import Control.Applicative ( (<$>) )
import Data.Time.Clock.POSIX
import Control.Exception as Exception (IOException(..),catch)

import Data.OpenPGP.Util.Fingerprint (fingerprint)

import qualified Crypto.Random as Vincent
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

hashAlgoDesc OpenPGP.MD5       = Vincent.hashDescrMD5
hashAlgoDesc OpenPGP.SHA1      = Vincent.hashDescrSHA1
hashAlgoDesc OpenPGP.RIPEMD160 = Vincent.hashDescrRIPEMD160
hashAlgoDesc OpenPGP.SHA256    = Vincent.hashDescrSHA256
hashAlgoDesc OpenPGP.SHA384    = Vincent.hashDescrSHA384
hashAlgoDesc OpenPGP.SHA512    = Vincent.hashDescrSHA512
hashAlgoDesc OpenPGP.SHA224    = Vincent.hashDescrSHA224
hashAlgoDesc _ =
       error "Unsupported HashAlgorithm in hashAlgoDesc"

find_key :: OpenPGP.Message -> String -> Maybe OpenPGP.Packet
find_key = OpenPGP.find_key fingerprint


privateDSAkey :: OpenPGP.Packet -> Vincent.DSA.PrivateKey
privateDSAkey k = Vincent.DSA.PrivateKey
    (Vincent.DSA.Params (keyParam 'p' k) (keyParam 'g' k) (keyParam 'q' k))
    (keyParam 'x' k)
privateRSAkey :: OpenPGP.Packet -> Vincent.RSA.PrivateKey
privateRSAkey k =
    -- Invert p and q because u is pinv not qinv
    Vincent.RSA.PrivateKey pubkey d q p
        (d `mod` (q-1))
        (d `mod` (p-1))
        (keyParam 'u' k)
    where
    d = keyParam 'd' k
    p = keyParam 'p' k
    q = keyParam 'q' k
    pubkey = rsaKey k

rsaKey :: OpenPGP.Packet -> Vincent.RSA.PublicKey
rsaKey k =
    Vincent.RSA.PublicKey (integerBytesize n) n (keyParam 'e' k)
    where
    n = keyParam 'n' k

integerBytesize :: Integer -> Int
integerBytesize i = fromIntegral $ LZ.length (encode (OpenPGP.MPI i)) - 2


toStrictBS :: LZ.ByteString -> BS.ByteString
toStrictBS = BS.concat . LZ.toChunks

toLazyBS :: BS.ByteString -> LZ.ByteString
toLazyBS = LZ.fromChunks . (:[])


keyParam :: Char -> OpenPGP.Packet -> Integer
keyParam c k = fromJustMPI $ lookup c (OpenPGP.key k)
fromJustMPI :: Maybe OpenPGP.MPI -> Integer
fromJustMPI (Just (OpenPGP.MPI x)) = x
fromJustMPI _ = error "Not a Just MPI, Data.OpenPGP.CryptoAPI"

hashBySymbol OpenPGP.MD5 = MD5.hashlazy
hashBySymbol OpenPGP.SHA1 = SHA1.hashlazy
hashBySymbol OpenPGP.SHA256 = SHA256.hashlazy
hashBySymbol OpenPGP.SHA384 = SHA384.hashlazy
hashBySymbol OpenPGP.SHA512 = SHA512.hashlazy
hashBySymbol OpenPGP.SHA224 = SHA224.hashlazy
hashBySymbol OpenPGP.RIPEMD160 = RIPEMD160.hashlazy




-- | Make a signature
--
-- In order to set more options on a signature, pass in a signature packet.
-- Operation is unsafe in that it silently re-uses "random" bytes when
-- entropy runs out.  Use pgpSign for a safer interface.
unsafeSign :: (Vincent.CPRG g) => -- CryptoRandomGen g) =>
	OpenPGP.Message          -- ^ SecretKeys, one of which will be used
	-> OpenPGP.SignatureOver -- ^ Data to sign, and optional signature packet
	-> OpenPGP.HashAlgorithm -- ^ HashAlgorithm to use in signature
	-> String                -- ^ KeyID of key to choose
	-> Integer               -- ^ Timestamp for signature (unless sig supplied)
	-> g                     -- ^ Random number generator
	-> (OpenPGP.SignatureOver, g)
unsafeSign keys over hsh keyid timestamp g = (over {OpenPGP.signatures_over = [sig]}, g')
	where
	(final, g') = case OpenPGP.key_algorithm sig of
		OpenPGP.DSA -> ([dsaR, dsaS], dsaG)
		kalgo | kalgo `elem` [OpenPGP.RSA,OpenPGP.RSA_S] -> ([toNum rsaFinal], g)
		      | otherwise ->
			error ("Unsupported key algorithm " ++ show kalgo ++ "in sign")
	(Vincent.DSA.Signature dsaR dsaS,dsaG) = let k' = privateDSAkey k in
		Vincent.DSA.sign g k' (dsaTruncate k' . bhash) dta
	(Right rsaFinal,_) = Vincent.RSA.signSafer g desc (privateRSAkey k) dta
	dsaTruncate (Vincent.DSA.PrivateKey (Vincent.DSA.Params _ _ q) _) = BS.take (integerBytesize q)
	dta     = toStrictBS $ encode over `LZ.append` OpenPGP.trailer sig
	sig     = findSigOrDefault (listToMaybe $ OpenPGP.signatures_over over)
	-- padding = emsa_pkcs1_v1_5_hash_padding hsh
	desc = hashAlgoDesc hsh
	bhash   = hashBySymbol hsh . toLazyBS
	toNum   = BS.foldl (\a b -> a `shiftL` 8 .|. fromIntegral b) 0
	Just k  = find_key keys keyid

	-- Either a SignaturePacket was found, or we need to make one
	findSigOrDefault (Just s) = OpenPGP.signaturePacket
		(OpenPGP.version s)
		(OpenPGP.signature_type s)
		(OpenPGP.key_algorithm k) -- force to algo of key
		hsh -- force hash algorithm
		(OpenPGP.hashed_subpackets s)
		(OpenPGP.unhashed_subpackets s)
		(OpenPGP.hash_head s)
		(map OpenPGP.MPI final)
	findSigOrDefault Nothing  = OpenPGP.signaturePacket
		4
		defaultStype
		(OpenPGP.key_algorithm k) -- force to algo of key
		hsh
		([
			-- Do we really need to pass in timestamp just for the default?
			OpenPGP.SignatureCreationTimePacket $ fromIntegral timestamp,
			OpenPGP.IssuerPacket $ fingerprint k
		] ++ (case over of
			OpenPGP.KeySignature  {} -> [OpenPGP.KeyFlagsPacket {
					OpenPGP.certify_keys = True,
					OpenPGP.sign_data = True,
					OpenPGP.encrypt_communication = False,
					OpenPGP.encrypt_storage = False,
					OpenPGP.split_key = False,
					OpenPGP.authentication = False,
					OpenPGP.group_key = False
				}]
			_ -> []
		))
		[]
		0 -- TODO
		(map OpenPGP.MPI final)

	defaultStype = case over of
		OpenPGP.DataSignature ld _
			| OpenPGP.format ld == 'b'     -> 0x00
			| otherwise                    -> 0x01
		OpenPGP.KeySignature {}           -> 0x1F
		OpenPGP.SubkeySignature {}        -> 0x18
		OpenPGP.CertificationSignature {} -> 0x13



now = floor <$> Data.Time.Clock.POSIX.getPOSIXTime

stampit timestamp sig = sig { OpenPGP.hashed_subpackets = hashed' }
 where
    hashed_stamps   = filter isStamp (OpenPGP.hashed_subpackets sig)
    unhashed_stamps = filter isStamp (OpenPGP.unhashed_subpackets sig)
    hashed' = case hashed_stamps ++ unhashed_stamps of
                [] -> OpenPGP.SignatureCreationTimePacket (fromIntegral timestamp)
                      : OpenPGP.hashed_subpackets sig
                _  -> OpenPGP.hashed_subpackets sig
    isStamp (OpenPGP.SignatureCreationTimePacket {}) = True
    isStamp _                                        = False

-- | Make a signature
--
-- In order to set more options on a signature, pass in a signature packet.
pgpSign :: 
    OpenPGP.Message          -- ^ SecretKeys, one of which will be used
    -> OpenPGP.SignatureOver -- ^ Data to sign, and optional signature packet
    -> OpenPGP.HashAlgorithm -- ^ HashAlgorithm to use in signature
    -> String                -- ^ KeyID of key to choose
    -> IO (Maybe OpenPGP.SignatureOver)
pgpSign seckeys dta hash_algo keyid =
    handleIO_ (return Nothing) $ do
    timestamp <- now
    -- g <- Thomas.newGenIO :: IO Thomas.SystemRandom
    g <- fmap Vincent.cprgCreate $ Vincent.createEntropyPool
    let _ = g :: Vincent.SystemRNG 
    let sigs = map (stampit timestamp) $ OpenPGP.signatures_over dta
        dta' = dta { OpenPGP.signatures_over = sigs }
    let (r,g') = unsafeSign seckeys dta' hash_algo keyid timestamp g
    return (Just r)

catchIO_ :: IO a -> IO a -> IO a
catchIO_ a h = Exception.catch a (\(_ :: IOException) -> h)

catchIO :: IO a -> (IOException -> IO a)  -> IO a
catchIO body handler = Exception.catch body handler

handleIO_ = flip catchIO_
handleIO = flip catchIO

