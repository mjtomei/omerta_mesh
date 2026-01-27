// OmertaMesh - Decentralized P2P Overlay Network
//
// A standalone transport layer providing:
// - Participant management (peer discovery, announcements)
// - Connection liveness (keepalives, failure detection)
// - Message routing (send to any peer via relay if needed)
// - Direct connection establishment (hole punching)

import Foundation
import Logging

/// Module-level logger
let meshLogger = Logger(label: "io.omerta.mesh")

/// Library version
public let omertaMeshVersion = "0.1.0"
