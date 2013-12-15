module Data.OpenPGP.Util.Verify where

import qualified Data.OpenPGP as OpenPGP
import Data.Maybe
import Data.Binary (encode)
import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LZ

import qualified Crypto.PubKey.DSA as Vincent.DSA
import qualified Crypto.PubKey.RSA.PKCS15 as Vincent.RSA

import Data.OpenPGP.Util.Base


dsaKey :: OpenPGP.Packet -> Vincent.DSA.PublicKey
dsaKey k = Vincent.DSA.PublicKey
    (Vincent.DSA.Params (keyParam 'p' k) (keyParam 'g' k) (keyParam 'q' k))
    (keyParam 'y' k)


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

