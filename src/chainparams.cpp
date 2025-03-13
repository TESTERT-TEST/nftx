// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Zcash' + blake2s(b'The Economist 2016-10-29 Known unknown: Another crypto-currency is born. BTC#436254 0000000000000000044f321997f336d2908cf8c8d6893e88dbf067e2d949487d ETH#2521903 483039a6b6bd8bd05f0584f9a078d075e454925eb71c1f13eaff59b405a721bb DJIA close on 27 Oct 2016: 18,169.68').hexdigest()
 *
 * CBlock(hash=00040fe8, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=c4eaa5, nTime=1477641360, nBits=1f07ffff, nNonce=4695, vtx=1)
 *   CTransaction(hash=c4eaa5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: c4eaa5
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Zcash0b9c4eef8b7cc417ee5001e3500984b6fea35683a7cac141a043c42064835d34";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
void *chainparams_commandline();
#include "komodo_defs.h"
int32_t ASSETCHAINS_BLOCKTIME = 60;
uint64_t ASSETCHAINS_NK[2];

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams()
    {

        strNetworkID = "main";
        strCurrencyUnits = "KMD";
        bip44CoinType = 141; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md 
        consensus.fCoinbaseMustBeProtected = false; // true this is only true wuth Verus and enforced after block 12800
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.powAlternate = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        consensus.nMaxFutureBlockTime = 7 * 60; // 7 mins

        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170005;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000281b32ff3198a1");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xee;
        pchMessageStart[2] = 0xe4;
        pchMessageStart[3] = 0x8d;
        vAlertPubKey = ParseHex("020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9");
        // (Zcash) vAlertPubKey = ParseHex("04b7ecf0baa90495ceb4e4090f6b2fd37eec1e9c85fac68a487f3ce11589692e4a317479316ee814e066638e1db54e37a10689b70286e6315b1087b6615d179264");
        nDefaultPort = 7770;
        nMinerThreads = 0;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        const size_t N = 192, K = 7;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1710602456;
        genesis.nBits    = KOMODO_MINDIFF_NBITS;
        genesis.nNonce   = uint256S("0x0000000000000000000000000000000000000000000000000000000000000004");
        genesis.nSolution = ParseHex("00b6473b4389666f411a7e484141b98d5d6188d0ea6fea413b50978d585a79a1b3effd839e9564912fa5a00e235acfe221982fb265dd3e29a2b374318bc0752b3d935e13718b9d57d5841b45e4d97565591214b23d78b6e57dc39f4a8eeb1085cbaf29ab0254444f9728c1732df3e5913370914a597df98e66df3efaca2a13efe23d7edb92296f72f68962a79de5553294a1e788bd7812950677bc79ce6fb45e6fb8f9c7f35750e2a2807919bb19852957134eb1c5d34be09a2e83d2b576a2258a621aee0be34481092c008f65ab9955c4eea18243432473479da54eed73f47c301de3e6f52cb05fc0c2f6913773834f22da39917a78c76b15ca2389f52f66fb12f1c94de6e7b276b8f4dfd2e6ba15f9e1e579377fa863f231a70d9a16b329871d675c15216214788196b45f0d047a3aaf0f10052bace31e2a46179533cff7929701eaa6e0309b2775b2d88fb785d072abc3b87143d0a8859a9a68cfa2ae19be5d315213cc03a0b38c6214acc4730923113c4c1ff1ac9621f4fcdb817420653c7d6826858a555731ea0d8eece8f23db1");

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x075c76f95f81403402e4cd6c2f6ceefdb8bd7a83661a09c636b22378f49c2931"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.push_back(CDNSSeedData("galaxywars.org", "node.galaxywars.org"));
        vSeeds.push_back(CDNSSeedData("galaxywars.org", "node1.galaxywars.org"));

        // TODO: we need more seed crawlers from other community members

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        base58Prefixes[CRYPTOCONDITION_ADDRESS] =     std::vector<unsigned char>(1,0x1c);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // guarantees the first two characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {22,154};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first two characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY] = {171,54};

        base58Prefixes[CRYPTOCONDITION_ADDRESS] =     std::vector<unsigned char>(1,0x1c);

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
};

static CMainParams mainParams;

void CChainParams::SetCheckpointData(CChainParams::CCheckpointData checkpointData)
{
    CChainParams::checkpointData = checkpointData;
}

/*
 To change the max block size, all that needs to be updated is the #define _MAX_BLOCK_SIZE in utils.h
 
 However, doing that without any other changes will allow forking non-updated nodes by creating a larger block. So, make sure to height activate the new blocksize properly.
 
 Assuming it is 8MB, then:
 #define _OLD_MAX_BLOCK_SIZE (4096 * 1024)
 #define _MAX_BLOCK_SIZE (2 * 4096 * 1024)
 
 change the body of if:
 {
    if ( height < saplinght+1000000 ) // activates 8MB blocks 1 million blocks after saplinght
        return(_OLD_MAX_BLOCK_SIZE);
    else return(_MAX_BLOCK_SIZE);
 }

*/

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TAZ";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 20000;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powAlternate = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nMaxFutureBlockTime = 7 * 60;

        vAlertPubKey = ParseHex("00");
        nDefaultPort = 17770;
        nMinerThreads = 0;
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 207500;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 280000;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000000001d0c4d9cd");

        pchMessageStart[0] = 0x5A;
        pchMessageStart[1] = 0x1F;
        pchMessageStart[2] = 0x7E;
        pchMessageStart[3] = 0x62;
        vAlertPubKey = ParseHex("020e46e79a2a8d12b9b5d12c7a91adb4e454edfae43c0a0cb805427d2ac7613fd9");
        nMaxTipAge = 24 * 60 * 60;

        nPruneAfterHeight = 1000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1296688602;
        genesis.nBits = KOMODO_MINDIFF_NBITS;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000009");
        genesis.nSolution = ParseHex("003423da3e41f916bf3ff0ee770eb844a240361abe08a8c9d46bd30226e2ad411a4047b6ddc230d173c60537e470e24f764120f5a2778b2a1285b0727bf79a0b085ad67e6266fb38fd72ef17f827315c42f921720248c983d4100e6ebd1c4b5e8762a973bac3bec7f7153b93752ebbb465f0fc9520bcfc30f9abfe303627338fed6ede9cf1b9173a736cf270cf4d9c6999ff4c3a301a78fd50dab6ccca67a0c5c2e41f216a1f3efd049a74bbe6252f9773bc309d3f9e554d996913ce8e1cec672a1fa4ea59726b61ea9e75d5ce9aa5dbfa96179a293810e02787f26de324fe7c88376ff57e29574a55faff7c2946f3e40e451861c32bf67da7377de3136858a18f34fab1bc8da37726ca2c25fc7b312a5427554ec944da81c7e27255d6c94ade9987ff7daedc2d1cc63d7d4cf93e691d13326fb1c7ee72ccdc0b134eb665fc6a9821e6fef6a6d45e4aac6dca6b505a0100ad56ea4f6fa4cdc2f0d1b65f730104a515172e34163bdb422f99d083e6eb860cf6b3f66642c4dbaf0d0fa1dca1b6166f1d1ffaa55a9d6d6df628afbdd14f1622c1c8303259299521a253bc28fcc93676723158067270fc710a09155a1e50c533e9b79ed5edba4ab70a08a9a2fc0eef0ddae050d75776a9804f8d6ad7e30ccb66c6a98d86710ca7a4dfb4feb159484796b9a015c5764aa3509051c87f729b9877ea41f8b470898c01388ed9098b1e006d3c30fc6e7c781072fa3f75d918505ee8ca75840fc62f67c57060666aa42578a2dd022eda62e3f1e447d7364074d34fd60ad9b138f60422afa6cfcb913fd6c213b496144dbfda7bfc7c24540cfe40ad0c0fd5a8c0902127f53d3178ba1b2a87bf1224d53d3a15e49ccdf121ae872a011c996d1b9793153cdcd4c0a7e99f8a35669788551cca2b62769eda24b6b55e2f4e0ac0d30aa50ecf33c6cdb24adfc922006a7bf434ced800fefe814c94c6fc8caa37b372d5088bb31d2f6b11a7a67ad3f70abbac0d5c256b637828de6cc525978cf151a2e50798e0c591787639a030291272c9ced3ab7d682e03f8c7db51f60163baa85315789666ea8c5cd6f789a7f4a5de4f8a9dfefce20f353cec606492fde8eab3e3b487b3a3a57434f8cf252a4b643fc125c8a5948b06744f5dc306aa587bdc85364c7488235c6edddd78763675e50a9637181519be06dd30c4ba0d845f9ba320d01706fd6dd64d1aa3cd4211a4a7d1d3f2c1ef2766d27d5d2cdf8e7f5e3ea309d4f149bb737305df1373a7f5313abe5986f4aa620bec4b0065d48aafac3631de3771f5c4d2f6eec67b09d9c70a3c1969fecdb014cb3c69832b63cc9d6efa378bff0ef95ffacdeb1675bb326e698f022c1a3a2e1c2b0f05e1492a6d2b7552388eca7ee8a2467ef5d4207f65d4e2ae7e33f13eb473954f249d7c20158ae703e1accddd4ea899f026618695ed2949715678a32a153df32c08922fafad68b1895e3b10e143e712940104b3b352369f4fe79bd1f1dbe03ea9909dbcf5862d1f15b3d1557a6191f54c891513cdb3c729bb9ab08c0d4c35a3ed67d517ffe1e2b7a798521aed15ff9822169c0ec860d7b897340bc2ef4c37f7eb73bd7dafef12c4fd4e6f5dd3690305257ae14ed03df5e3327b68467775a90993e613173fa6650ffa2a26e84b3ce79606bf234eda9f4053307f344099e3b10308d3785b8726fd02d8e94c2759bebd05748c3fe7d5fe087dc63608fb77f29708ab167a13f32da251e249a544124ed50c270cfc6986d9d1814273d2f0510d0d2ea335817207db6a4a23ae9b079967b63b25cb3ceea7001b65b879263f5009ac84ab89738a5b8b71fd032beb9f297326f1f5afa630a5198d684514e242f315a4d95fa6802e82799a525bb653b80b4518ec610a5996403b1391");
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"));

        vFixedSeeds.clear();
        vSeeds.clear();
        //vSeeds.push_back(CDNSSeedData("z.cash", "dns.testnet.z.cash")); // Komodo

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[CRYPTOCONDITION_ADDRESS] =     std::vector<unsigned char>(1,0x1c);

        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {20,81};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]  = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY] = {177,235};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        //fRequireRPCPassword = true;
        fMiningRequiresPeers = false;//true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock)
            (38000, uint256S("0x001e9a2d2e2892b88e9998cf7b079b41d59dd085423a921fe8386cecc42287b8")),
            1486897419,  // * UNIX timestamp of last checkpoint block
            47163,       // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            715          //   total number of tx / (checkpoint block height / (24 * 24))
        };
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.powAlternate = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 17;
        consensus.nMaxFutureBlockTime = 7 * 60; // 7 mins
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0x8e;
        pchMessageStart[2] = 0xf3;
        pchMessageStart[3] = 0xf5;
        nMinerThreads = 1;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(
            1296688602,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000009"),
            ParseHex("01936b7db1eb4ac39f151b8704642d0a8bda13ec547d54cd5e43ba142fc6d8877cab07b3"),


            KOMODO_MINDIFF_NBITS, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327"));
        assert(genesis.hashMerkleRoot == uint256S("0xc4eaa58879081de3c24a7b117ed2b28300e7ec4c4c1dff1d3f1268b7857a4ddb"));

        nDefaultPort = 17779;
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        base58Prefixes[CRYPTOCONDITION_ADDRESS] =     std::vector<unsigned char>(1,0x1c);

        //base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        //base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        //base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vFoundersRewardAddress = { "t2FwcEhFdNXuFMv1tcYwaBJtYVtMj8b1uTg" };
        assert(vFoundersRewardAddress.size() <= consensus.GetLastFoundersRewardBlockHeight());
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);

    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

int32_t MAX_BLOCK_SIZE(int32_t height)
{
    int32_t saplinght = pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight;
    //fprintf(stderr,"MAX_BLOCK_SIZE %d vs. %d\n",height,mainParams.consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight);
    if ( height <= 0 || (saplinght > 0 && height >= saplinght) )
    {
        return(_MAX_BLOCK_SIZE);
    }
    else return(2000000);
}

void komodo_setactivation(int32_t height)
{
    pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = height;
    pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = height;
    ASSETCHAINS_SAPLING = height;
    fprintf(stderr,"SET SAPLING ACTIVATION height.%d\n",height);
}

void *chainparams_commandline()
{
    fprintf(stderr,"chainparams_commandline called\n");
    CChainParams::CCheckpointData checkpointData;
    //fprintf(stderr,">>>>>>>> port.%u\n",ASSETCHAINS_P2PPORT);
    if ( ASSETCHAINS_SYMBOL[0] != 0 )
    {
        if ( ASSETCHAINS_BLOCKTIME != 60 )
        {
            pCurrentParams->consensus.nMaxFutureBlockTime = 7 * ASSETCHAINS_BLOCKTIME; // 7 blocks
            pCurrentParams->consensus.nPowTargetSpacing = ASSETCHAINS_BLOCKTIME;
        }
        pCurrentParams->SetDefaultPort(ASSETCHAINS_P2PPORT);
        if ( ASSETCHAINS_NK[0] != 0 && ASSETCHAINS_NK[1] != 0 )
        {
            //BOOST_STATIC_ASSERT(equihash_parameters_acceptable(ASSETCHAINS_NK[0], ASSETCHAINS_NK[1]));
            pCurrentParams->SetNValue(ASSETCHAINS_NK[0]);
            pCurrentParams->SetKValue(ASSETCHAINS_NK[1]);
        }
        if ( KOMODO_TESTNODE != 0 )
            pCurrentParams->SetMiningRequiresPeers(false);
        if ( ASSETCHAINS_RPCPORT == 0 )
            ASSETCHAINS_RPCPORT = ASSETCHAINS_P2PPORT + 1;
        pCurrentParams->pchMessageStart[0] = ASSETCHAINS_MAGIC & 0xff;
        pCurrentParams->pchMessageStart[1] = (ASSETCHAINS_MAGIC >> 8) & 0xff;
        pCurrentParams->pchMessageStart[2] = (ASSETCHAINS_MAGIC >> 16) & 0xff;
        pCurrentParams->pchMessageStart[3] = (ASSETCHAINS_MAGIC >> 24) & 0xff;
        fprintf(stderr,">>>>>>>>>> %s: p2p.%u rpc.%u magic.%08x %u %u coins\n",ASSETCHAINS_SYMBOL,ASSETCHAINS_P2PPORT,ASSETCHAINS_RPCPORT,ASSETCHAINS_MAGIC,ASSETCHAINS_MAGIC,(uint32_t)ASSETCHAINS_SUPPLY);
        if (ASSETCHAINS_ALGO == ASSETCHAINS_VERUSHASH)
        {
            // this is only good for 60 second blocks with an averaging window of 45. for other parameters, use:
            // nLwmaAjustedWeight = (N+1)/2 * (0.9989^(500/nPowAveragingWindow)) * nPowTargetSpacing
            pCurrentParams->consensus.nLwmaAjustedWeight = 1350;
            pCurrentParams->consensus.nPowAveragingWindow = 45;
            pCurrentParams->consensus.powAlternate = uint256S("00000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        }
        else if (ASSETCHAINS_ALGO == ASSETCHAINS_VERUSHASHV1_1)
        {
            // this is only good for 60 second blocks with an averaging window of 45. for other parameters, use:
            // nLwmaAjustedWeight = (N+1)/2 * (0.9989^(500/nPowAveragingWindow)) * nPowTargetSpacing
            pCurrentParams->consensus.nLwmaAjustedWeight = 1350;
            pCurrentParams->consensus.nPowAveragingWindow = 45;
            pCurrentParams->consensus.powAlternate = uint256S("0000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        }

        if (ASSETCHAINS_LWMAPOS != 0)
        {
            pCurrentParams->consensus.posLimit = uint256S("000000000f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
            pCurrentParams->consensus.nPOSAveragingWindow = 45;
            // spacing is 1000 units per block to get better resolution, POS is 50% hard coded for now, we can vary it later
            // when we get reliable integer math on nLwmaPOSAjustedWeight
            pCurrentParams->consensus.nPOSTargetSpacing = VERUS_BLOCK_POSUNITS * 2;
            // nLwmaPOSAjustedWeight = (N+1)/2 * (0.9989^(500/nPOSAveragingWindow)) * nPOSTargetSpacing
            // this needs to be recalculated if VERUS_BLOCK_POSUNITS is changed
            pCurrentParams->consensus.nLwmaPOSAjustedWeight = 46531;
        }

        // only require coinbase protection on Verus from the Komodo family of coins
        if (strcmp(ASSETCHAINS_SYMBOL,"VRSC") == 0)
        {
            pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 227520;
            pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 227520;
            pCurrentParams->consensus.fCoinbaseMustBeProtected = true;
            checkpointData = //(Checkpoints::CCheckpointData)
                    {
                            boost::assign::map_list_of
                                    (0, pCurrentParams->consensus.hashGenesisBlock)
                                    (10000, uint256S("0xac2cd7d37177140ea4991cf630c0b9c7f94d707b84fb0351bf3a44856d2ae5dc"))
                                    (20000, uint256S("0xb0e8cb9f77aaa7ff5bd90d6c08d06f4c4bf03e00c2b8a35a042e760845590c8a"))
                                    (30000, uint256S("0xf2112ca577338ad7104bf905fa6a63d36b17a86f914c97b73cd31d43fcd7557c"))
                                    (40000, uint256S("0x00000000008f83378dab727864b763ce91a4ea5f75d55939c0c1390cfb8c38f1"))
                                    (49170, uint256S("0x2add646c0089871ec2379f02f7cd60b3af6efd9c152a6f16fc10925458c270cc")),
                            (int64_t)1529910234,    // * UNIX timestamp of last checkpoint block
                            (int64_t)63661,         // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
                            (double)2777            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
                    };

            pCurrentParams->consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000001a8f4f23f8b2d1f7e");
        }
        else
        {
            if (strcmp(ASSETCHAINS_SYMBOL,"VRSCTEST") == 0 || strcmp(ASSETCHAINS_SYMBOL,"VERUSTEST") == 0)
            {
                pCurrentParams->consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000001f7e");
            }
            pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = ASSETCHAINS_SAPLING;
            pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = ASSETCHAINS_OVERWINTER;
            checkpointData = //(Checkpoints::CCheckpointData)
                    {
                            boost::assign::map_list_of
                                    (0, pCurrentParams->consensus.hashGenesisBlock),
                            (int64_t)1231006505,
                            (int64_t)1,
                            (double)2777            // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
                    };
        }
    }
    else
    {
        checkpointData = // (Checkpoints::CCheckpointData)
            {
                boost::assign::map_list_of

                (0, pCurrentParams->consensus.hashGenesisBlock)
                (	50000,	uint256S("0x00076e16d3fa5194da559c17cf9cf285e21d1f13154ae4f7c7b87919549345aa"))
                (	100000,	uint256S("0x0f02eb1f3a4b89df9909fec81a4bd7d023e32e24e1f5262d9fc2cc36a715be6f"))
                (	150000,	uint256S("0x0a817f15b9da636f453a7a01835cfc534ed1a55ce7f08c566471d167678bedce"))
                (	200000,	uint256S("0x000001763a9337328651ca57ac487cc0507087be5838fb74ca4165ff19f0e84f"))
                (	250000,	uint256S("0x0dd54ef5f816c7fde9d2b1c8c1a26412b3c761cc5dd3901fa5c4cd1900892fba"))
                (	300000,	uint256S("0x000000fa5efd1998959926047727519ed7de06dcf9f2cd92a4f71e907e1312dc"))
                (	350000,	uint256S("0x0000000228ef321323f81dae00c98d7960fc7486fb2d881007fee60d1e34653f"))
                (	400000,	uint256S("0x036d294c5be96f4c0efb28e652eb3968231e87204a823991a85c5fdab3c43ae6"))
                (	450000,	uint256S("0x0906ef1e8dc194f1f03bd4ce1ac8c6992fd721ef2c5ccbf4871ec8cdbb456c18"))
                (	500000,	uint256S("0x0bebdb417f7a51fe0c36fcf94e2ed29895a9a862eaa61601272866a7ecd6391b"))
                (	550000,	uint256S("0x06df52fc5f9ba03ccc3a7673b01ab47990bd5c4947f6e1bc0ba14d21cd5bcccd"))
                (	600000,	uint256S("0x00000005080d5689c3b4466e551cd1986e5d2024a62a79b1335afe12c42779e4"))
                (	650000,	uint256S("0x039a3cb760cc6e564974caf69e8ae621c14567f3a36e4991f77fd869294b1d52"))
                (	700000,	uint256S("0x00002285be912b2b887a5bb42d2f1aa011428c565b0ffc908129c47b5ce87585"))
                (	750000,	uint256S("0x04cff4c26d185d591bed3613ce15e1d15d9c91dd8b98a6729f89c58ce4bd1fd6"))
                (	800000,	uint256S("0x0000000617574d402fca8e6570f0845bd5fe449398b318b4e1f65bc69cdd6606"))
                (	850000,	uint256S("0x044199301f37194f20ba7b498fc72ed742f6c0ba6e476f28d6c81d225e58d5ce"))
                (	900000,	uint256S("0x08bdbe4de2a65ac89fd2913192d05362c900e3af476a0c99d9f311875067451e"))
                (	950000,	uint256S("0x0000000aa9a44b593e6138f247bfae75bd43b9396ef9ff0a6a3ebd852f131806"))
                (	1000000,	uint256S("0x0cb1d2457eaa58af5028e86e27ac54578fa09558206e7b868ebd35e7005ed8bb"))
                (	1050000,	uint256S("0x044d49bbc3bd9d32b6288b768d4f7e0afe3cbeda606f3ac3579a076e4bddf6ae"))
                (	1100000,	uint256S("0x000000050cad04887e170059dd2556d85bbd20390b04afb9b07fb62cafd647b4"))
                (	1150000,	uint256S("0x0c85501c759d957dd1ccc5f7fdfcc415c89c7f2a26471fffc75b75f79e63c16a"))
                (	1200000,	uint256S("0x0763cbf43ed7227988081c29d9e9fc7ab2450216e6d0354cc4596c86689702d4"))
                (	1250000,	uint256S("0x0489640207f8c343a56a10e45d987516059ea82a3c6859a771b3a9cf94f5c3bb"))
                (	1300000,	uint256S("0x000000012a01709b254b4f75e2b9ed772d8fe558655c8c859892ca8c9d625e87"))
                (	1350000,	uint256S("0x075a1a5c66a68b47d9848ca6986687ed2665b1852457051bf142208e62f98a60"))
                (	1400000,	uint256S("0x055f73dd9b20650c3d6e6dbb606af8d9479e4c81d89430867abff5329f167bb2"))
                (	1450000,	uint256S("0x014c2926e07e9712211c5e82f05df1b802c59cc8bc24e3cc9b09942017080f2d"))
                (	1500000,	uint256S("0x0791f892210ce3c513ab607d689cd1e8907a27f3dfeb58dec21ae299b7981cb7"))
                (	1550000,	uint256S("0x08fcbaffb7164b161a25efc6dd5c70b679498ee637d663fe201a55c7decc37a3"))
                (	1600000,	uint256S("0x0e577dcd49319a67fe2acbb39ae6d46afccd3009d3ba9d1bcf6c624708e12bac"))
                (	1615921,	uint256S("0x049140623cc54a4a3d5868f720611e180ba0cafa21eab1edd0bc9ec2e6b7c374")),
                1573604104,     // * UNIX timestamp of last checkpoint block
                7371665,         // * total number of transactions between genesis and last checkpoint
                                //   (the tx=... number in the SetBestChain debug.log lines)
                2777            // * estimated number of transactions per day after checkpoint
                                //   total number of tx / (checkpoint block height / (24 * 24))
            };
    }

    pCurrentParams->SetCheckpointData(checkpointData);

    ASSETCHAIN_INIT = 1;
    return(0);
}
