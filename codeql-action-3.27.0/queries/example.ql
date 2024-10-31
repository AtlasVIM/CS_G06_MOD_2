/**
 * @name Path Traversal Vulnerability
 * @description Detects instances where user-controlled input is used to construct file paths, potentially allowing path traversal attacks.
 * @kind path-problem
 * @id java/path-traversal
 * @tags security, path-traversal
 */

import ja   va
import semmle.code.java.dataflow.DataFlow
class PathTraversalConfig extends TaintTracking::Configuration {
    PathTraversalConfig() { this = "PathTraversalConfig" }
  
    override predicate isSource(DataFlow::Node source) {
      // Define sources, like HTTP request parameters or form inputs
      source.asExpr() instanceof Method.getParameter(0)
        and source.asExpr().getMethod().getName() = "getParameter";
    }
  
    override predicate isSink(DataFlow::Node sink) {
      // Define sinks, such as File constructors or file stream classes
      exists (MethodAccess ma |
        ma.getMethod().getDeclaringType().hasName("java.io.File") and
        ma.getMethod().getName() = "File")
    }
  }
  
from PathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), "Potential path traversal vulnerability: user-controlled input is used in file operations."
  