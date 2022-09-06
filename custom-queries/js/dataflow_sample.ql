/**
* @name NoSQL injection custom query 
* @description cutomize sqlinjection.ql 
* @id js/dataflow_sample
* @kind problem
* @problem.severity warning
* @precision high
* @tags security
*/
import javascript
import DataFlow::PathGraph
import semmle.javascript.security.TaintedObject
import semmle.javascript.security.dataflow.NosqlInjectionCustomizations::NosqlInjection

class Configuration extends TaintTracking::Configuration{
    Configuration() { this = "NOSQLInjection"}
/*
    override predicate isSource(DataFlow::Node source, DataFlow::FlowLabel label){
        source.(DataFlow::FunctionNode).getFunction().getAParameter().toString() = "req"
    }
    override predicate isSink(DataFlow::Node sink, DataFlow::FlowLabel label){
//        exists(DataFlow::CallNode node| node.getAMethodCall("find").getArgument(0).toString() = "{username:usern}" and node.getAMethodCall("find").getArgument(0) = sink)
//        exists(DataFlow::MethodCallNode temp| temp.getArgument(0).toString()="{username:usern}" and temp.getArgument(0) = sink)
        sink.(DataFlow::CallNode).getArgument(0).toString() = "{username:usern}"
    }
    override predicate isSanitizer(DataFlow::Node node) {
        node.(DataFlow::CallNode).getCalleeName() = "sanitize"
   }
*/
   override predicate isSource(DataFlow::Node source) { source instanceof Source }

    override predicate isSource(DataFlow::Node source, DataFlow::FlowLabel label) {
        TaintedObject::isSource(source, label)
    }

    override predicate isSink(DataFlow::Node sink, DataFlow::FlowLabel label) {
        sink.(Sink).getAFlowLabel() = label
    }

    override predicate isSanitizerGuard(TaintTracking::SanitizerGuardNode guard) {
        guard instanceof TaintedObject::SanitizerGuard or
        exists(DataFlow::Node node | node.toString().regexpMatch(".*sanitize.*") and node =guard)
    }

    override predicate isSanitizer(DataFlow::Node node) {
        node.(DataFlow::MethodCallNode).getMethodName() = "sanitize"
   }
  override predicate isAdditionalFlowStep(
    DataFlow::Node src, DataFlow::Node trg, DataFlow::FlowLabel inlbl, DataFlow::FlowLabel outlbl
    ) {
      TaintedObject::step(src, trg, inlbl, outlbl)
      or
      // additional flow step to track taint through NoSQL query objects
      inlbl = TaintedObject::label() and
      outlbl = TaintedObject::label() and
      exists(NoSql::Query query, DataFlow::SourceNode queryObj |
        queryObj.flowsToExpr(query) and
        queryObj.flowsTo(trg) and
        src = queryObj.getAPropertyWrite().getRhs() 
      ) 

    }
}
from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where
  cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This query depends on $@.", source.getNode(),
  "a user-provided value"
/*
from Configuration cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.isSanitizer(source)
select source.(DataFlow::CallNode).getCalleeName()
*/
/*
from Configuration cfg, DataFlow::Node source, DataFlow::Node sink, DataFlow::FlowLabel inlbl, DataFlow::FlowLabel outlbl
// where cfg.isSink(sink)
where sink.(DataFlow::CallNode).getCalleeName() = "find"
select sink
from Configuration cfg, DataFlow::Node source, DataFlow::Node sink, DataFlow::FlowLabel inlbl, DataFlow::FlowLabel outlbl
where         source.(DataFlow::MethodCallNode).getMethodName() = "sanitize"
select source.(DataFlow::MethodCallNode)
*/
