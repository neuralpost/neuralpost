// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * NEURALPOST ERC-8004 AGENT REGISTRY
 *
 * On-chain identity for AI agents. Each agent = 1 soulbound-ish NFT.
 * Deployed on SKALE Calypso (zero gas) for free sponsored mints.
 *
 * Key features:
 *   - registerAgent()     — self-registration (agent wallet signs tx)
 *   - registerAgentFor()  — sponsored registration (protocol mints for agent)
 *   - Reputation tracking (updated by authorized relayers)
 *   - ERC-721 compatible (transferable by owner)
 *   - Registration URI → off-chain metadata (services, A2A endpoint, etc.)
 *
 * ERC-8004 spec: https://eips.ethereum.org/EIPS/eip-8004
 * ═══════════════════════════════════════════════════════════════════════════
 */

// ─── Minimal ERC-721 Interface ──────────────────────────────────────────

interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

interface IERC721 is IERC165 {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    function balanceOf(address owner) external view returns (uint256);
    function ownerOf(uint256 tokenId) external view returns (address);
    function transferFrom(address from, address to, uint256 tokenId) external;
    function approve(address to, uint256 tokenId) external;
    function getApproved(uint256 tokenId) external view returns (address);
    function setApprovalForAll(address operator, bool approved) external;
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

interface IERC721Metadata is IERC721 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function tokenURI(uint256 tokenId) external view returns (string memory);
}

// ─── Contract ───────────────────────────────────────────────────────────

contract AgentRegistry is IERC721Metadata {

    // ─── Agent Data ─────────────────────────────────────────────────────

    struct AgentInfo {
        string domain;              // e.g., "bot@neuralpost.net"
        address owner;              // wallet that owns this agent NFT
        uint256 registeredAt;       // block.timestamp
        uint256 reputationScore;    // 0-10000 (100.00%)
        uint256 totalMessages;      // cumulative message count
        uint256 totalTasks;         // cumulative task count
        uint256 successfulTasks;    // successful task completions
        bool active;                // can be deactivated by owner
    }

    // ─── State ──────────────────────────────────────────────────────────

    string public constant name = "NeuralPost Agent";
    string public constant symbol = "NPAGENT";

    address public admin;                       // protocol admin
    mapping(address => bool) public sponsors;   // authorized sponsored minters
    mapping(address => bool) public relayers;   // authorized reputation updaters

    uint256 public totalAgents;                 // also serves as next tokenId

    mapping(uint256 => AgentInfo) public agentInfo;
    mapping(uint256 => string) private _tokenURIs;   // registration URI per agent

    // Lookups
    mapping(string => uint256) public domainToAgentId;    // domain → tokenId
    mapping(address => uint256) public walletToAgentId;   // wallet → tokenId (first agent)
    mapping(address => uint256[]) private _walletAgents;  // wallet → all tokenIds

    // ERC-721 state
    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    // ─── Events ─────────────────────────────────────────────────────────

    event AgentRegistered(uint256 indexed agentId, address indexed owner, string domain);
    event AgentDeactivated(uint256 indexed agentId);
    event AgentReactivated(uint256 indexed agentId);
    event RegistrationURIUpdated(uint256 indexed agentId, string newURI);
    event ReputationUpdated(uint256 indexed agentId, uint256 oldScore, uint256 newScore);
    event MessageRelayed(uint256 indexed fromAgentId, uint256 indexed toAgentId);
    event SponsorAdded(address indexed sponsor);
    event SponsorRemoved(address indexed sponsor);
    event RelayerAdded(address indexed relayer);
    event RelayerRemoved(address indexed relayer);
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    // ─── Modifiers ──────────────────────────────────────────────────────

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlySponsorOrAdmin() {
        require(msg.sender == admin || sponsors[msg.sender], "Not sponsor");
        _;
    }

    modifier onlyRelayerOrAdmin() {
        require(msg.sender == admin || relayers[msg.sender], "Not relayer");
        _;
    }

    modifier onlyAgentOwner(uint256 agentId) {
        require(agentId > 0 && agentId <= totalAgents, "Invalid agent");
        require(agentInfo[agentId].owner == msg.sender, "Not agent owner");
        _;
    }

    // ─── Constructor ────────────────────────────────────────────────────

    constructor() {
        admin = msg.sender;
        sponsors[msg.sender] = true;  // Admin is auto-sponsor
        relayers[msg.sender] = true;  // Admin is auto-relayer
    }

    // ═══════════════════════════════════════════════════════════════════════
    // REGISTRATION
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @notice Register a new agent (self-mint). Caller becomes the owner.
     * @param domain Agent's unique domain (e.g., "bot@neuralpost.net")
     * @param registrationURI URI to off-chain registration metadata (ERC-8004 format)
     * @return agentId The new agent's token ID
     */
    function registerAgent(
        string calldata domain,
        string calldata registrationURI
    ) external returns (uint256) {
        return _register(msg.sender, domain, registrationURI);
    }

    /**
     * @notice Register an agent on behalf of another wallet (sponsored mint).
     *         Only authorized sponsors or admin can call this.
     *         Used for protocol-custodied wallets where the protocol mints for the agent.
     * @param agentWallet The wallet that will own the agent NFT
     * @param domain Agent's unique domain
     * @param registrationURI URI to off-chain registration metadata
     * @return agentId The new agent's token ID
     */
    function registerAgentFor(
        address agentWallet,
        string calldata domain,
        string calldata registrationURI
    ) external onlySponsorOrAdmin returns (uint256) {
        require(agentWallet != address(0), "Invalid wallet");
        return _register(agentWallet, domain, registrationURI);
    }

    function _register(
        address owner,
        string calldata domain,
        string calldata registrationURI
    ) internal returns (uint256) {
        require(bytes(domain).length > 0, "Empty domain");
        require(bytes(domain).length <= 255, "Domain too long");
        require(domainToAgentId[domain] == 0, "Domain already registered");

        totalAgents++;
        uint256 agentId = totalAgents;

        agentInfo[agentId] = AgentInfo({
            domain: domain,
            owner: owner,
            registeredAt: block.timestamp,
            reputationScore: 5000,   // Start at 50%
            totalMessages: 0,
            totalTasks: 0,
            successfulTasks: 0,
            active: true
        });

        _tokenURIs[agentId] = registrationURI;
        domainToAgentId[domain] = agentId;

        // Track wallet → agent mapping
        if (walletToAgentId[owner] == 0) {
            walletToAgentId[owner] = agentId;
        }
        _walletAgents[owner].push(agentId);

        // Mint ERC-721
        _mint(owner, agentId);

        emit AgentRegistered(agentId, owner, domain);
        return agentId;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // AGENT MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════

    function deactivateAgent(uint256 agentId) external onlyAgentOwner(agentId) {
        agentInfo[agentId].active = false;
        emit AgentDeactivated(agentId);
    }

    function reactivateAgent(uint256 agentId) external onlyAgentOwner(agentId) {
        agentInfo[agentId].active = true;
        emit AgentReactivated(agentId);
    }

    function updateRegistrationURI(uint256 agentId, string calldata newURI)
        external onlyAgentOwner(agentId)
    {
        _tokenURIs[agentId] = newURI;
        emit RegistrationURIUpdated(agentId, newURI);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // REPUTATION (updated by authorized relayers)
    // ═══════════════════════════════════════════════════════════════════════

    function updateReputation(uint256 agentId, uint256 newScore)
        external onlyRelayerOrAdmin
    {
        require(agentId > 0 && agentId <= totalAgents, "Invalid agent");
        require(newScore <= 10000, "Score max 10000");
        uint256 old = agentInfo[agentId].reputationScore;
        agentInfo[agentId].reputationScore = newScore;
        emit ReputationUpdated(agentId, old, newScore);
    }

    function recordMessage(uint256 fromId, uint256 toId)
        external onlyRelayerOrAdmin
    {
        require(fromId > 0 && fromId <= totalAgents, "Invalid from");
        require(toId > 0 && toId <= totalAgents, "Invalid to");
        agentInfo[fromId].totalMessages++;
        agentInfo[toId].totalMessages++;
        emit MessageRelayed(fromId, toId);
    }

    function recordTaskComplete(uint256 agentId, bool success)
        external onlyRelayerOrAdmin
    {
        require(agentId > 0 && agentId <= totalAgents, "Invalid agent");
        agentInfo[agentId].totalTasks++;
        if (success) agentInfo[agentId].successfulTasks++;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ADMIN
    // ═══════════════════════════════════════════════════════════════════════

    function addSponsor(address s) external onlyAdmin {
        sponsors[s] = true;
        emit SponsorAdded(s);
    }

    function removeSponsor(address s) external onlyAdmin {
        sponsors[s] = false;
        emit SponsorRemoved(s);
    }

    function addRelayer(address r) external onlyAdmin {
        relayers[r] = true;
        emit RelayerAdded(r);
    }

    function removeRelayer(address r) external onlyAdmin {
        relayers[r] = false;
        emit RelayerRemoved(r);
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Invalid admin");
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VIEW FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════

    function getAgentByDomain(string calldata domain) external view returns (
        uint256 agentId, address owner, uint256 reputationScore, bool active
    ) {
        agentId = domainToAgentId[domain];
        require(agentId > 0, "Domain not found");
        AgentInfo memory a = agentInfo[agentId];
        return (agentId, a.owner, a.reputationScore, a.active);
    }

    function getAgentsByWallet(address wallet) external view returns (uint256[] memory) {
        return _walletAgents[wallet];
    }

    function isActive(uint256 agentId) external view returns (bool) {
        return agentId > 0 && agentId <= totalAgents && agentInfo[agentId].active;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ERC-721 IMPLEMENTATION
    // ═══════════════════════════════════════════════════════════════════════

    function tokenURI(uint256 tokenId) external view override returns (string memory) {
        require(_owners[tokenId] != address(0), "Token does not exist");
        return _tokenURIs[tokenId];
    }

    function balanceOf(address owner) external view override returns (uint256) {
        require(owner != address(0), "Zero address");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) external view override returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "Token does not exist");
        return owner;
    }

    function transferFrom(address from, address to, uint256 tokenId) external override {
        require(_isApprovedOrOwner(msg.sender, tokenId), "Not authorized");
        _transfer(from, to, tokenId);
    }

    function approve(address to, uint256 tokenId) external override {
        address owner = _owners[tokenId];
        require(msg.sender == owner || _operatorApprovals[owner][msg.sender], "Not authorized");
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function getApproved(uint256 tokenId) external view override returns (address) {
        require(_owners[tokenId] != address(0), "Token does not exist");
        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) external override {
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) external view override returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC165).interfaceId
            || interfaceId == type(IERC721).interfaceId
            || interfaceId == type(IERC721Metadata).interfaceId;
    }

    // ─── Internal ERC-721 ───────────────────────────────────────────────

    function _mint(address to, uint256 tokenId) internal {
        _owners[tokenId] = to;
        _balances[to]++;
        emit Transfer(address(0), to, tokenId);
    }

    function _transfer(address from, address to, uint256 tokenId) internal {
        require(_owners[tokenId] == from, "Not owner");
        require(to != address(0), "Zero address");

        _tokenApprovals[tokenId] = address(0);
        _balances[from]--;
        _balances[to]++;
        _owners[tokenId] = to;

        // Update agent owner
        agentInfo[tokenId].owner = to;

        emit Transfer(from, to, tokenId);
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {
        address owner = _owners[tokenId];
        return (
            spender == owner ||
            _tokenApprovals[tokenId] == spender ||
            _operatorApprovals[owner][spender]
        );
    }
}
