
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ZenAccess {
    address public owner;

    struct RoleData {
        mapping(address => bool) members;
        string description;
    }

    mapping(bytes32 => RoleData) private _roles;
    mapping(address => string[]) public userRoles;

    event RoleCreated(bytes32 indexed roleId, string description);
    event RoleGranted(bytes32 indexed roleId, address indexed account);
    event RoleRevoked(bytes32 indexed roleId, address indexed account);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyRole(bytes32 roleId) {
        require(_roles[roleId].members[msg.sender], "Access denied");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function createRole(string memory description) external onlyOwner returns (bytes32) {
        bytes32 roleId = keccak256(abi.encodePacked(description));
        require(bytes(_roles[roleId].description).length == 0, "Role already exists");

        _roles[roleId].description = description;

        emit RoleCreated(roleId, description);
        return roleId;
    }

    function grantRole(bytes32 roleId, address account) external onlyOwner {
        require(!_roles[roleId].members[account], "Already has role");

        _roles[roleId].members[account] = true;
        userRoles[account].push(_roles[roleId].description);

        emit RoleGranted(roleId, account);
    }

    function revokeRole(bytes32 roleId, address account) external onlyOwner {
        require(_roles[roleId].members[account], "Doesn't have role");

        _roles[roleId].members[account] = false;
        emit RoleRevoked(roleId, account);
    }

    function hasRole(bytes32 roleId, address account) public view returns (bool) {
        return _roles[roleId].members[account];
    }

    function getRoleDescription(bytes32 roleId) public view returns (string memory) {
        return _roles[roleId].description;
    }

    function getUserRoles(address user) public view returns (string[] memory) {
        return userRoles[user];
    }
}
