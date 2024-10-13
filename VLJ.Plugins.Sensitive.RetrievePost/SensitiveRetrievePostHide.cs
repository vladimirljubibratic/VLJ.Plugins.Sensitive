using Microsoft.Xrm.Sdk.Query;
using Microsoft.Xrm.Sdk;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace VLJ.Plugins.Sensitive.RetrievePost
{
    public class SensitiveRetrievePostHide : PluginBase
    {
        public override void Execute(PluginContextBase context)
        {
            // Your code here
            try
            {
                //PluginTracer.TraceContext;
                context.Trace("Start");

                Guid userID = context.Context.InitiatingUserId;
                string roleName = "Sensitive Data";
                bool hasRole = false;

                QueryExpression query = new QueryExpression("systemuserroles");
                query.Criteria.AddCondition("systemuserid", ConditionOperator.Equal, userID);

                LinkEntity link = query.AddLink("role", "roleid", "roleid", JoinOperator.Inner);
                link.LinkCriteria.AddCondition("name", ConditionOperator.Equal, roleName);

                EntityCollection results = context.RetrieveMultiple(query);

                hasRole = results.Entities.Count > 0;


                if (context.Context.OutputParameters.Contains("BusinessEntityCollection"))
                {
                    var retrievedResult = (EntityCollection)context.Context.OutputParameters["BusinessEntityCollection"];

                    foreach (Entity entity in retrievedResult.Entities)
                    {
                        if (!hasRole)
                        {
                            var secret = entity.GetAttributeValue<Boolean>("vlj_secret");

                            if (secret)
                            {
                                //entity.Attributes.Remove("vlj_sensitivefield");
                                entity.Attributes["vlj_sensitivefield"] = "*";
                            }
                        }
                    }

                }
            }

            catch (FaultException<OrganizationServiceFault> ex)
            {
                throw new InvalidPluginExecutionException("An error occurred in RetrieveMultipleSensitive plugin.", ex);
            }

            catch (Exception ex)
            {
                Trace.TraceInformation("RetrieveMultipleSensitive plugin: {0}", ex.ToString());
                throw;
            }
        }
    }
}
