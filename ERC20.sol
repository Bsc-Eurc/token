/**
 *Submitted for verification at BscScan.com on 2026-02-24
*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * EURC (EURC) — ERC20 with EIP-2612 permit, owner rescues, and industry-standard hardening.
 * - Name: Bsc Eurc
 * - Symbol: EURC
 * - Decimals: 18
 * - Type: Stable Coin
 * - Initial supply (human): 100,000,000 (minted to deployer)
 *
 * Notes:
 * - initial supply is provided in whole tokens and auto-scaled by decimals internally.
 * - decimals capped to 18 to avoid accidental overflow.
 * - permit includes signature malleability checks (v in {27,28}, s in lower half-order).
 */
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;

interface IERC1271 {
    function isValidSignature(bytes32 _hash, bytes memory _signature) external view returns (bytes4);
}
abstract contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyGovernor() {
        require(msg.sender == owner, "Ownable: caller is not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyGovernor {
        require(newOwner != address(0), "Ownable: zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

contract EURC is IERC20, Ownable {
    string public name;
    string public symbol;
    uint8 public immutable decimals;

    uint256 private _totalSupply;
    
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    mapping(address => uint256) public nonces;

    // add near top of contract
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    // EIP-712 domain/cache
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;
    address private immutable _CACHED_THIS;

    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;
    bytes32 private constant _TYPE_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // secp256k1n/2
    bytes32 private constant SECP256K1N_HALVED = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    event TokensRescued(address indexed token, address indexed to, uint256 amount);
    event ETHRescued(address indexed to, uint256 amount);

    /// @notice Deploys Bsc EURC and mints 10,000,000 whole tokens to deployer
    constructor() {
        string memory _name = "Eurc-Bsc";
        string memory _symbol = "EURC";
        uint8 _decimals = 18;
        uint256 initialSupplyWhole = 100_000_000; // human-friendly

        require(bytes(_name).length != 0 && bytes(_symbol).length != 0, "metadata empty");
        require(_decimals <= 18, "decimals > 18 not supported");

        name = _name;
        symbol = _symbol;
        decimals = _decimals;

        _status = _NOT_ENTERED;

        _HASHED_NAME = keccak256(bytes(_name));
        _HASHED_VERSION = keccak256(bytes("1"));
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_THIS = address(this);
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION);

        uint256 scaled = initialSupplyWhole * (10 ** uint256(_decimals));
        _mint(msg.sender, scaled);
    }

    /* ----------------------- ERC20 standard ----------------------- */
    function totalSupply() external view override returns (uint256) { return _totalSupply; }
    function balanceOf(address account) external view override returns (uint256) { return _balances[account]; }
    function allowance(address owner_, address spender) external view override returns (uint256) { return _allowances[owner_][spender]; }

    // Remove incorrect function and add proper renounceOwnership()
    function renounceOwnership() external onlyGovernor {
        emit OwnershipTransferred(owner, address(0));
        owner = address(0);
    }

    function transfer(address recipient, uint256 amount) external override returns (bool) {
        _transfer(msg.sender, recipient, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) external override returns (bool) {
        uint256 currentAllowance = _allowances[sender][msg.sender];
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
            unchecked { _approve(sender, msg.sender, currentAllowance - amount); }
        }
        _transfer(sender, recipient, amount);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        _approve(msg.sender, spender, _allowances[msg.sender][spender] + addedValue);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 current = _allowances[msg.sender][spender];
        require(current >= subtractedValue, "ERC20: decreased allowance below zero");
        unchecked { _approve(msg.sender, spender, current - subtractedValue); }
        return true;
    }

    /* ----------------------- Internal helpers ----------------------- */
    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "ERC20: transfer from zero");
        require(to != address(0), "ERC20: transfer to zero");
        uint256 bal = _balances[from];
        require(bal >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[from] = bal - amount;
            _balances[to] += amount;
        }
        emit Transfer(from, to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        require(to != address(0), "ERC20: mint to zero");
        _totalSupply += amount;
        _balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function euCollateralReservesSupply(uint256 amount) external onlyGovernor nonReentrant{
        require(amount > 0, "Invalid amount");
        _mint(msg.sender, amount);
    }

    function _burn(address from, uint256 amount) internal {
        require(from != address(0), "ERC20: burn from zero");
        uint256 bal = _balances[from];
        require(bal >= amount, "ERC20: burn amount exceeds balance");
        unchecked {
            _balances[from] = bal - amount;
            _totalSupply -= amount;
        }
        emit Transfer(from, address(0), amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function _approve(address owner_, address spender, uint256 amount) internal {
        require(owner_ != address(0), "ERC20: approve from zero");
        require(spender != address(0), "ERC20: approve to zero");
        _allowances[owner_][spender] = amount;
        emit Approval(owner_, spender, amount);
    }

    /* ----------------------- EIP-712 / EIP-2612 ----------------------- */
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return (address(this) == _CACHED_THIS && block.chainid == _CACHED_CHAIN_ID)
            ? _CACHED_DOMAIN_SEPARATOR
            : _buildDomainSeparator(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION);
    }

    function _buildDomainSeparator(bytes32 typeHash, bytes32 nameHash, bytes32 versionHash) private view returns (bytes32) {
        return keccak256(abi.encode(typeHash, nameHash, versionHash, block.chainid, address(this)));
    }

    // --- Add this constant near other constants ---
    bytes32 private constant _MASK_SIGN = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff; // 2**255 - 1
    bytes4 constant internal ERC1271_MAGICVALUE = 0x1626ba7e;

    function permit(
    address owner_,
    address spender,
    uint256 value,
    uint256 deadline,
    bytes calldata signature
    ) external {
        require(owner_ != address(0), "permit: owner zero");
        require(block.timestamp <= deadline, "ERC20Permit: expired deadline");

        uint256 nonce = nonces[owner_];
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner_, spender, value, nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));

        bool valid;

        if (owner_.code.length > 0) {
            // Contract wallet path: pass raw signature bytes to ERC-1271
            try IERC1271(owner_).isValidSignature(digest, signature) returns (bytes4 magic) {
                valid = (magic == ERC1271_MAGICVALUE);
            } catch {
                valid = false;
            }
        } else {
            // EOA path: recover signer from signature (supports 65 and EIP-2098 64)
            address recovered = _recoverEOA(digest, signature);
            valid = (recovered != address(0) && recovered == owner_);
        }

        require(valid, "ERC20Permit: invalid signature");

        unchecked { nonces[owner_] = nonce + 1; }
        _approve(owner_, spender, value);
    }

    /// @dev Recover EOA signer from signature. Supports 65-byte (r,s,v) and 64-byte (r,vs) EIP-2098.
    function _recoverEOA(bytes32 digest, bytes calldata signature) internal pure returns (address) {
        uint256 sigLen = signature.length;

        if (sigLen == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // solhint-disable-next-line no-inline-assembly
            assembly {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 32))
                v := byte(0, calldataload(add(signature.offset, 64)))
            }
            // normalize v if 0/1
            if (v < 27) v += 27;
            // v must be 27 or 28
            if (!(v == 27 || v == 28)) return address(0);
            // s must be in lower half order
            if (uint256(s) > uint256(SECP256K1N_HALVED)) return address(0);
            // recover
            return ecrecover(digest, v, r, s);
        } else if (sigLen == 64) {
            // EIP-2098 short signature: r (32) || vs (32) where vs's highest bit is v (0/1) and rest is s
            bytes32 r;
            bytes32 vs;
            // solhint-disable-next-line no-inline-assembly
            assembly {
                r := calldataload(signature.offset)
                vs := calldataload(add(signature.offset, 32))
            }
            // extract s and v
            bytes32 s = bytes32(uint256(vs) & uint256(_MASK_SIGN));
            uint8 v = uint8((uint256(vs) >> 255) + 27); // 0/1 -> 27/28
            // v must be 27 or 28
            if (!(v == 27 || v == 28)) return address(0);
            if (uint256(s) > uint256(SECP256K1N_HALVED)) return address(0);
            return ecrecover(digest, v, r, s);
        } else {
            return address(0);
        }
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    /* ----------------------- Rescue functions (owner only) ----------------------- */
    function rescueERC20(address token, address to, uint256 amount) external onlyGovernor nonReentrant {
        require(to != address(0), "rescue: zero recipient");
        require(token != address(this), "rescue: cannot rescue this token");
        require(amount > 0, "rescue: zero amount");
        require(IERC20(token).balanceOf(address(this)) >= amount,"rescue: insufficient token balance");
        IERC20(token).safeTransfer(to, amount);
        emit TokensRescued(token, to, amount);
    }

    function rescueETH(address payable to, uint256 amount) external onlyGovernor nonReentrant {
        require(to != address(0), "rescueETH: zero recipient");
        require(amount > 0, "rescueETH: zero amount");
        require(address(this).balance >= amount, "rescueETH: insufficient balance");

        (bool success, ) = to.call{value: amount}("");
        require(success, "rescueETH: transfer failed");
        emit ETHRescued(to, amount);
    }

    receive() external payable {}
    fallback() external payable {}
}
