using Microsoft.Xrm.Sdk.Query;
using Microsoft.Xrm.Sdk;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.ServiceModel;
using System.Runtime.Remoting.Services;
using System.Xml.Linq;


namespace VLJ.Plugins.Sensitive.RetrievePost
{
    public class SensitiveRetrievePreStop : PluginBase
    {
        public override void Execute(PluginContextBase context)
        {
            // Your code here
            if (context.Context.InputParameters.Contains("Query"))
            {
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

                    if (!hasRole)
                    {
                        var thisQuery = context.Context.InputParameters["Query"];
                        var queryExpressionQuery = thisQuery as QueryExpression;
                        var queryByAttributeQuery = thisQuery as QueryByAttribute;

                        if (thisQuery is FetchExpression fetchExpressionQuery)
                        {
                            context.Trace("Found FetchExpression Query");

                            XDocument fetchXmlDoc = XDocument.Parse(fetchExpressionQuery.Query);
                            //The required entity element
                            var entityElement = fetchXmlDoc.Descendants("entity").FirstOrDefault();
                            var entityName = entityElement.Attributes("name").FirstOrDefault().Value;

                            //Only applying to the account entity
                            if (entityName == "account")
                            {
                                context.Trace("Query on Account confirmed");

                                //Get all filter elements
                                var filterElements = entityElement.Descendants("filter");

                                //Find any existing vlj_sensitivefield conditions
                                var sensitiveFieldConditions = from c in filterElements.Descendants("condition")
                                                          where c.Attribute("attribute").Value.Equals("vlj_sensitivefield")
                                                          select c;

                                if (sensitiveFieldConditions.Count() > 0)
                                {
                                    context.Trace("Removing existing vlj_sensitivefield filter conditions.");

                                    //Remove statecode conditions
                                    sensitiveFieldConditions.ToList().ForEach(x => x.Remove());


                                    //Optionally, add the condition you want in a new filter
                                    //entityelement.add(
                                    //    new xelement("filter",
                                    //        new xelement("condition",
                                    //            new xattribute("attribute", "vlj_sensitivefield"),
                                    //            new xattribute("operator", "neq"), //not equal
                                    //            new xattribute("value", "*") //all *
                                    //            )
                                    //        )
                                    //    );

                                    fetchExpressionQuery.Query = fetchXmlDoc.ToString();
                                    context.Trace("Posted query: " + fetchXmlDoc.ToString());
                                    // throw new InvalidPluginExecutionException("You do not have rights to filter Sensitive Field.");
                                    SendAppNotification(context.Service, userID);
                                }
                            }

                        }
                        if (queryExpressionQuery != null)
                        {
                            context.Trace("Found Query Expression Query");
                            if (queryExpressionQuery.EntityName.Equals("account"))
                            {
                                context.Trace("Query on Account confirmed");

                                //Recursively remove any conditions referring to the statecode attribute
                                foreach (FilterExpression fe in queryExpressionQuery.Criteria.Filters)
                                {
                                    //Remove any existing criteria based on statecode attribute
                                    RemoveAttributeConditions(fe, "vlj_sensitivefield", context.Tracer);
                                }

                                //Opptionaly, define the filter
                                //var sensitiveFieldFilter = new FilterExpression();
                                //sensitiveFieldFilter.AddCondition("vlj_sensitivefield", ConditionOperator.NotEqual, "*");
                                //Add it to the Criteria
                                //queryExpressionQuery.Criteria.AddFilter(sensitiveFieldFilter);
                            }

                        }
                        if (queryByAttributeQuery != null)
                        {
                            context.Trace("Found Query By Attribute Query");
                            //Query by attribute doesn't provide a complex query model that 
                            // can be manipulated
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

        /// <summary>
        /// Removes any conditions using a specific named attribute
        /// </summary>
        /// <param name="filter">The filter that may have a condition using the attribute</param>
        /// <param name="attributeName">The name of the attribute that should not be used in a condition</param>
        /// <param name="tracingService">The tracing service to use</param>
        private void RemoveAttributeConditions(FilterExpression filter, string attributeName, ITracingService tracingService)
        {

            List<ConditionExpression> conditionsToRemove = new List<ConditionExpression>();

            foreach (ConditionExpression ce in filter.Conditions)
            {
                if (ce.AttributeName.Equals(attributeName))
                {
                    conditionsToRemove.Add(ce);
                }
            }

            conditionsToRemove.ForEach(x =>
            {
                filter.Conditions.Remove(x);
                tracingService.Trace("Removed existing filter conditions.");
            });

            foreach (FilterExpression fe in filter.Filters)
            {
                RemoveAttributeConditions(fe, attributeName, tracingService);
            }
        }

        /// <summary>
        /// Example of SendAppNotification
        /// </summary>
        /// <param name="service">Authenticated client implementing the IOrganizationService interface</param>
        /// <param name="userId">The Id of the user to send the notification to.</param>
        /// <returns>The app notification id</returns>
        public static Guid SendAppNotification(IOrganizationService service, Guid userId)
        {
            var request = new OrganizationRequest()
            {
                RequestName = "SendAppNotification",
                Parameters = new ParameterCollection
                {
                    ["Title"] = "Sensitive Data Filtering",
                    ["Recipient"] = new EntityReference("systemuser", userId),
                    ["Body"] = "You do not have rights to filter Sensitive Data!",
                    ["IconType"] = new OptionSetValue(100000000), //info
                    ["ToastType"] = new OptionSetValue(200000000) //timed
                }
            };

            OrganizationResponse response = service.Execute(request);
            return (Guid)response.Results["NotificationId"];
        }


    }
}
