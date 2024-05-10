pragma solidity ^0.8.0;

contract RansomwareProofOfLife {
    uint256 public ransomAmount;
    address public attacker;
    uint256 public constant SAMPLE_PERCENTAGE = 20;
    uint256 public constant DEADLINE_DURATION = 24 hours;
    uint256 public totalFiles;
    
    struct Victim {
        bytes32 commitment;
        uint256 paymentTimestamp;
        bool paid;
    }
    
    mapping(string => Victim) public victims;
    mapping(string => mapping(string => bool)) public sampleDecrypted;
    mapping(string => address) public victimAddresses;
    mapping(string => string[]) public fileSampleRequests;
    
    event SampleDecryptionRequested(string victimID, string[] sampleIDs);
    event SampleDecryptionKeyRevealed(string victimID, string sampleID, bytes32 decryptionKey);
    event RansomPaid(string victimID, uint256 amount);
    event MasterKeyRevealed(string victimID, bytes32 masterKey);
    
    constructor() {
        ransomAmount = 0.00001 ether;
        attacker = msg.sender;
        totalFiles = 10;
    }
    
    modifier onlyAttacker() {
        require(msg.sender == attacker, "Only attacker can perform this action");
        _;
    }
    
    modifier onlyVictim(string memory victimID) {
        require(msg.sender == victimAddresses[victimID], "Only victim can perform this action");
        _;
    }
    
    function registerVictim(string memory victimID) external {
        require(victimAddresses[victimID] == address(0), "Victim already registered");
        victimAddresses[victimID] = msg.sender;
        victims[victimID].commitment = 0;
    }
    
    function requestSamplesDecryption(string memory victimID, string[] memory sampleIDs) external onlyVictim(victimID) {
        require(sampleIDs.length <=  SAMPLE_PERCENTAGE * totalFiles / 100, "Exceeded sample limit");
        
        for (uint256 i = 0; i < sampleIDs.length; i++) {
            require(!sampleDecrypted[victimID][sampleIDs[i]], "Sample already decrypted");
            sampleDecrypted[victimID][sampleIDs[i]] = true;
        }
        
        fileSampleRequests[victimID] = sampleIDs;
        emit SampleDecryptionRequested(victimID, sampleIDs);
    }
    
    function getFileIDs(string memory victimID) external view onlyAttacker returns (string[] memory) {
        return fileSampleRequests[victimID];
    }
    
    function revealSamplesDecryptionKeys(string memory victimID, string[] memory sampleIDs, bytes32[] memory decryptionKeys) external onlyAttacker {
        require(sampleIDs.length == decryptionKeys.length, "Mismatch in arrays length");
        
        for (uint256 i = 0; i < sampleIDs.length; i++) {
            require(sampleDecrypted[victimID][sampleIDs[i]], "Sample not requested for decryption");
            emit SampleDecryptionKeyRevealed(victimID, sampleIDs[i], decryptionKeys[i]);
        }
    }
    
    function payRansom(string memory victimID, bytes32 commitment) external payable onlyVictim(victimID) {
        require(msg.value >= ransomAmount, "Insufficient ransom amount");
        require(victims[victimID].paid ==false, "Ransom already paid");
        victims[victimID] = Victim(commitment, block.timestamp, true);
        emit RansomPaid(victimID, msg.value);
    }
    
    function revealMasterKey(string memory victimID, bytes32 masterKey) external onlyAttacker {
        require(victims[victimID].paid, "Ransom not paid");
        require(victims[victimID].commitment == sha256(abi.encodePacked(masterKey)), "Invalid master key");
        
        emit MasterKeyRevealed(victimID, masterKey);
        // Transfer the ransom to the attacker's address if everything goes perfectly
        payable(attacker).transfer(address(this).balance);
        
    }
    
    function refundRansom(string memory victimID) external onlyVictim(victimID) {
        require(victims[victimID].paid, "Ransom not paid");
        require(block.timestamp >= victims[victimID].paymentTimestamp + DEADLINE_DURATION, "Deadline not reached");
        
        payable(msg.sender).transfer(ransomAmount);
        victims[victimID].paid = false;
        delete victims[victimID];
    }
}
