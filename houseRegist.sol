// SPDX-License-Identifier: MIT
pragma solidity 0.8.17 ;


interface IAssetToken {
    function mint(address to) external returns (uint256);
}

abstract contract Initializable {
    /**
     * @dev Indicates that the contract has been initialized.
     */
    bool private _initialized;

    /**
     * @dev Indicates that the contract is in the process of being initialized.
     */
    bool private _initializing;

    /**
     * @dev Modifier to protect an initializer function from being invoked twice.
     */
    modifier initializer() {
        require(_initializing || !_initialized, "Initializable: contract is already initialized");

        bool isTopLevelCall = !_initializing;
        if (isTopLevelCall) {
            _initializing = true;
            _initialized = true;
        }

        _;

        if (isTopLevelCall) {
            _initializing = false;
        }
    }
}

contract Ownable is Initializable{
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    function __Ownable_init_unchained() internal initializer {
        address msgSender = msg.sender;
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(isOwner(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Returns true if the caller is the current owner.
     */
    function isOwner() public view returns (bool) {
        return msg.sender == _owner;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public onlyOwner {
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     */
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

contract HouseRegist is Initializable,Ownable {
    using SafeMath for uint256;
    bytes32 public DOMAIN_SEPARATOR;
    uint256 public nodeNum;
    mapping(address => uint256) nodeAddrIndex;
    mapping(uint256 => address) public nodeIndexAddr;
    mapping(address => bool) public nodeAddrSta;
    mapping(uint256 => bool) public indexSta;
    event AddNodeAddr(address[] nodeAddrs);
    event DeleteNodeAddr(address[] nodeAddrs);
    event RegisteredAssets(address  userAddr, address assetAddr, uint256 indexId, uint256 tokenId);
    
    struct Data {
        address userAddr;
        address assetAddr;
        uint256 indexId;
        uint256 expiration;
    }

    struct Sig {
        /* v parameter */
        uint8 v;
        /* r parameter */
        bytes32 r;
        /* s parameter */
        bytes32 s;
    }

    function init()  external initializer{
        __Ownable_init_unchained();
        __HouseRegist_init_unchained();
    }

    function __HouseRegist_init_unchained() internal initializer{
        uint chainId;
        assembly {
            chainId := chainId
        }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256('EIP712Domain(uint256 chainId,address verifyingContract)'),
                chainId,
                address(this)
            )
        );
    }

    receive() payable external{

    }

    fallback() payable external{

    }

    function addNodeAddr(address[] calldata _nodeAddrs) external onlyOwner{
        for (uint256 i = 0; i< _nodeAddrs.length; i++){
            address _nodeAddr = _nodeAddrs[i];
            require(!nodeAddrSta[_nodeAddr], "This node is already a node address");
            nodeAddrSta[_nodeAddr] = true;
            uint256 _nodeAddrIndex = nodeAddrIndex[_nodeAddr];
            if (_nodeAddrIndex == 0){
                _nodeAddrIndex = ++nodeNum;
                nodeAddrIndex[_nodeAddr] = _nodeAddrIndex;
                nodeIndexAddr[_nodeAddrIndex] = _nodeAddr;
            }
        }
        emit AddNodeAddr(_nodeAddrs);
    }

    function deleteNodeAddr(address[] calldata _nodeAddrs) external onlyOwner{
        for (uint256 i = 0; i< _nodeAddrs.length; i++){
            address _nodeAddr = _nodeAddrs[i];
            require(nodeAddrSta[_nodeAddr], "This node is not a pledge node");
            nodeAddrSta[_nodeAddr] = false;
            uint256 _nodeAddrIndex = nodeAddrIndex[_nodeAddr];
            if (_nodeAddrIndex > 0){
                uint256 _nodeNum = nodeNum;
                address _lastNodeAddr = nodeIndexAddr[_nodeNum];
                nodeAddrIndex[_lastNodeAddr] = _nodeAddrIndex;
                nodeIndexAddr[_nodeAddrIndex] = _lastNodeAddr;
                nodeAddrIndex[_nodeAddr] = 0;
                nodeIndexAddr[_nodeNum] = address(0x0);
                nodeNum--;
            }
        }
        emit DeleteNodeAddr(_nodeAddrs);
    }

    function registeredAssets(
        address userAddr,
        address assetAddr,
        uint256 indexId,
        uint256 expiration,
        uint8[] calldata vs,
        bytes32[] calldata rssMetadata
    )
        external
    {
        require( userAddr == msg.sender , "Signing users are not the same as trading users");
        require( block.timestamp <= expiration, "The transaction exceeded the time limit");
        require( !indexSta[indexId], "The indexId has been used");
        indexSta[indexId] = true;
        uint256 len = vs.length;
        uint256 counter;
        require(len*2 == rssMetadata.length, "Signature parameter length mismatch");
        bytes32 digest = getDigest(Data(userAddr, assetAddr, indexId, expiration));
        for (uint256 i = 0; i < len; i++) {
            bool result = verifySign(
                digest,
                Sig(vs[i], rssMetadata[i*2], rssMetadata[i*2+1])
            );
            if (result){
                counter++;
            }
        }
        require(
            counter > nodeNum/2,
            "The number of signed accounts did not reach the minimum threshold"
        );
        _registeredAssets(userAddr, assetAddr, indexId);
    }
 
    function _registeredAssets(address userAddr, address assetAddr, uint256 indexId) internal {
        uint256 tokenId = IAssetToken(assetAddr).mint(userAddr);
        emit RegisteredAssets(userAddr, assetAddr, indexId, tokenId);
    }

    function queryNode() external view returns (address[] memory) {
        address[] memory _addrArray = new address[](nodeNum);
        uint256 j;
        if (nodeNum >= 0){
            for (uint256 i = 1; i <= nodeNum; i++) {
                _addrArray[j] = nodeIndexAddr[i];
                j++;
            }
        }
        return (_addrArray);
    }

    function verifySign(bytes32 _digest,Sig memory _sig) internal view returns (bool)  {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 hash = keccak256(abi.encodePacked(prefix, _digest));
        address _nodeAddr = ecrecover(hash, _sig.v, _sig.r, _sig.s);
        require(_nodeAddr !=address(0),"Illegal signature");
        return nodeAddrSta[_nodeAddr];
    }
    
    function getDigest(Data memory _data) internal view returns(bytes32 digest){
        digest = keccak256(
            abi.encodePacked(
                '\x19\x01',
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(_data.userAddr, _data.assetAddr,  _data.indexId, _data.expiration))
            )
        );
    }
    
}
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}
