/**
* @name NoSQL_injection_custom_query 
* @description cutomize sqlinjection.ql 
* @id js/dataflow_sample
* @kind path-problem
* @problem.severity warning
* @security-severity 8.8
* @precision high
* @tags security
*/

import javascript
import semmle.javascript.security.TaintedObject
import semmle.javascript.security.dataflow.NosqlInjectionCustomizations::NosqlInjection
import DataFlow::PathGraph

class MyMongoSanitize extends TaintTracking::SanitizerGuardNode, DataFlow::CallNode {
  MyMongoSanitize() { this.getCalleeName() = "sanitize" }
  override predicate sanitizes(boolean outcome, Expr e){
    outcome = true and
    e = getArgument(0).asExpr()
  }
}
class Configuration extends TaintTracking::Configuration{
    Configuration() { this = "NOSQLInjection"}
/*
    override predicate isSource(DataFlow::Node source){
       source.getAstNode().toString().regexpMatch(".*req.body.username.*")
//      source instanceof Source
    }
*/
  override predicate isSource(DataFlow::Node source, DataFlow::FlowLabel label) {
    TaintedObject::isSource(source, label)
  }
  /*
    override predicate isSink(DataFlow::Node sink){
      exists(DataFlow::Node tmp|tmp.getAstNode().toString().regexpMatch(".*req.body.*") and tmp.getASuccessor().toString() = "usern")
  }
  */
  override predicate isSink(DataFlow::Node sink, DataFlow::FlowLabel label) {
    sink.(Sink).getAFlowLabel() = label
  }

  override predicate isSanitizerGuard(TaintTracking::SanitizerGuardNode guard){
    guard instanceof MyMongoSanitize
  }

  override predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ, DataFlow::FlowLabel inlbl, DataFlow::FlowLabel outlbl){
    TaintedObject::step(pred, succ, inlbl, outlbl)
    or
    // additional flow step to track taint through NoSQL query objects
    inlbl = TaintedObject::label() and
    outlbl = TaintedObject::label() and
    exists(NoSql::Query query, DataFlow::SourceNode queryObj |
      queryObj.flowsToExpr(query) and
      queryObj.flowsTo(succ) and
      pred = queryObj.getAPropertyWrite().getRhs()
    )
  }
/*
  override predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ, DataFlow::FlowLabel inlbl, DataFlow::FlowLabel outlbl){
    inlbl = TaintedObject::label() and
    outlbl = TaintedObject::label() and
    exists(NoSql::Query query, DataFlow::SourceNode queryObj |
      queryObj.flowsToExpr(query) and
      queryObj.flowsTo(succ) and
      pred = queryObj.getAPropertyWrite().getRhs()
    )
  }
  */
}
/*
from Configuration cfg, DataFlow::Node source, DataFlow::Node sink
//where cfg.hasFlowPath(source, sink) and source.getNode().toString() != sink.getNode().toString()
//where cfg.hasFlowPath(source, sink) and source.getNode().toString() != sink.getNode().toString()
// select sink.getNode(), source, sink, "This query depends on $@.", source.getNode(), "a user-provided value"
where cfg.hasFlow(source, sink)
select sink.getNode(), source, sink, "This query depends on $@.", source.getNode(),
  "a user-provided value"
*/
from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, "Property access originating $@." , source, "here"
/*
from Configuration cfg, DataFlow::Node source
where source.getFile().getBaseName() = "app.js" and source.(DataFlow::CallNode).getCalleeName() = "sanitize"
select source.(DataFlow::CallNode).getArgument(0).asExpr()
*/

/*
// select source, source.asExpr()
//where source.(DataFlow::MethodCallNode).getCalleeNode().toString().regexpMatch("mongoS.*")
  from CheckPathSanitizerGuard cfg, DataFlow::Node source
  where cfg.sanitizes(true, source.asExpr())
  select source
  */
