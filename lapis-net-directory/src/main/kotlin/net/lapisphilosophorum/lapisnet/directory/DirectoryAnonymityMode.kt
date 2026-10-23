package net.lapisphilosophorum.lapisnet.directory

/**
 * Whether this node publishes itself into the directory the classic way ([OFF]: address-bearing
 * [PeerRecord], DHT value, rendezvous provider records) or under the anonymity rules of wave V0.10.0-D
 * ([ON]: only an [AnonymousPeerRecord], published through a circuit; nothing address-bearing leaves the node).
 *
 * The default is [OFF] everywhere. Wave E maps the `--anonymity` flag onto it. This mode alone does NOT make
 * the node anonymous: the transport key is still the identity key (see docs/anonymity.adoc, leak inventory).
 */
enum class DirectoryAnonymityMode { OFF, ON }
