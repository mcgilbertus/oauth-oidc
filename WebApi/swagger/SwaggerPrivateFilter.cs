using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace WebApi.swagger;

public class SwaggerPrivateFilter: IDocumentFilter
{
    public void Apply(OpenApiDocument swaggerDoc, DocumentFilterContext context)
    {
        var privateRoutes = swaggerDoc.Paths
            .Where(p => p.Key.Contains("/private"))
            .ToList();
        foreach (var privateRoute in privateRoutes)
        {
            swaggerDoc.Paths.Remove(privateRoute.Key);
        }
    }
}