using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

public class Vulnerability
{
    public string Tipo { get; set; }
    public string Codigo { get; set; }
    public NivelRisco Risco { get; set; }
    public List<int> Linhas { get; set; }

    public Vulnerability(string type, string node, NivelRisco riskLevel, List<int> lineNumbers)
    {
        Tipo = type;
        Codigo = node;
        Risco = riskLevel;
        Linhas = lineNumbers;
    }
}

public enum NivelRisco
{
    Alto,
    Medio,
    Baixo
}
public static class VulnerabilidadeAnalyzer
{
    static List<Vulnerability> vulnerabilities;

    public static List<Vulnerability> AnalisarVulnerabilidades(SyntaxNode root)
    {
        vulnerabilities = new List<Vulnerability>();

        // Analisar vulnerabilidades de XSS
        AnalyzeForXSS(root);

        // Analisar vulnerabilidades de SQL Injection
        //var sqlVulnerabilities = AnalyzeSQLInjection(root);
        //vulnerabilities.AddRange(sqlVulnerabilities);

        return vulnerabilities;
    }

    private static VariableDeclarationSyntax FindVariableDeclaration(IdentifierNameSyntax identifierName, SyntaxNode root)
    {
        var variableDeclarations = root.DescendantNodes()
            .OfType<VariableDeclarationSyntax>();

        foreach (var variableDeclaration in variableDeclarations)
        {
            foreach (var variable in variableDeclaration.Variables)
            {
                if (variable.Identifier.Text == identifierName.Identifier.Text)
                {
                    return variableDeclaration;
                }
            }
        }

        return null;
    }


    private static void AnalyzeSQLInjection(SyntaxNode root)
    {
        var objectCreations = root.DescendantNodes()
            .OfType<ObjectCreationExpressionSyntax>();

        foreach (var objectCreation in objectCreations)
        {
            // Check if the object being created is a SqlCommand
            if (objectCreation.Type.ToString() == "SqlCommand")
            {
                var arguments = objectCreation.ArgumentList.Arguments;
                foreach (var argument in arguments)
                {
                    var expression = argument.Expression;

                    if (expression is IdentifierNameSyntax identifierName)
                    {
                        // Find the variable declaration for the identifier
                        var variableDeclaration = FindVariableDeclaration(identifierName, root);
                        if (variableDeclaration != null)
                        {
                            // Check if the variable is initialized with a concatenation
                            var initializer = variableDeclaration.Variables.First().Initializer;
                            if (initializer?.Value is BinaryExpressionSyntax binaryExpression &&
                                binaryExpression.IsKind(SyntaxKind.AddExpression))
                            {
                                var lineSpan = objectCreation.GetLocation().GetLineSpan();
                                var lines = new List<int> { lineSpan.StartLinePosition.Line + 1 };

                                vulnerabilities.Add(new Vulnerability(
                                    "SQL Injection",
                                    objectCreation.ToString(),
                                    NivelRisco.Alto,
                                    lines
                                ));
                            }
                        }
                    }
                    else if (expression is LiteralExpressionSyntax ||
                             expression is InterpolatedStringExpressionSyntax)
                    {
                        // Detect if the SQL command string is a literal or interpolated string
                        var lineSpan = objectCreation.GetLocation().GetLineSpan();
                        var lines = new List<int> { lineSpan.StartLinePosition.Line + 1 };

                        vulnerabilities.Add(new Vulnerability(
                            "SQL Injection",
                            objectCreation.ToString(),
                            NivelRisco.Alto,
                            lines
                        ));
                    }
                    else if (expression is BinaryExpressionSyntax binaryExpression)
                    {
                        // Check if the argument is a concatenated string
                        if (binaryExpression.IsKind(SyntaxKind.AddExpression))
                        {
                            var lineSpan = objectCreation.GetLocation().GetLineSpan();
                            var lines = new List<int> { lineSpan.StartLinePosition.Line + 1 };

                            vulnerabilities.Add(new Vulnerability(
                                "SQL Injection",
                                objectCreation.ToString(),
                                NivelRisco.Alto,
                                lines
                            ));
                        }
                    }
                    else if (expression is InvocationExpressionSyntax)
                    {
                        // Handle complex cases like method invocations
                        var lineSpan = objectCreation.GetLocation().GetLineSpan();
                        var lines = new List<int> { lineSpan.StartLinePosition.Line + 1 };

                        vulnerabilities.Add(new Vulnerability(
                            "Potential SQL Injection",
                            objectCreation.ToString(),
                            NivelRisco.Medio,
                            lines
                        ));
                    }
                }
            }
        }
    }

    static void AnalyzeForXSS(SyntaxNode root)
    {
        var methodInvocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in methodInvocations)
        {
            // Verificar se o método invocado é Request.QueryString
            if (invocation.ToString().Contains("Request.QueryString"))
            {
                // Verificar se há uma invocação de Server.HtmlEncode com o valor de Request.QueryString
                var htmlEncodeInvocations = invocation.Ancestors().OfType<InvocationExpressionSyntax>()
                    .Where(inv => inv.ToString().Contains("Server.HtmlEncode"));

                if (!htmlEncodeInvocations.Any())
                {
                    // Se não houver Server.HtmlEncode para o valor de Request.QueryString, adicionar vulnerabilidade
                    var tipo = "XSS";
                    var codigo = "Vulnerabilidade de XSS detectada: Falha ao codificar valor do QueryString.";
                    var risco = NivelRisco.Alto; // Ajuste conforme necessário
                    var linha = invocation.GetLocation().GetLineSpan().StartLinePosition.Line +1;
                    var lineNumbers = new List<int>() { linha };
                    vulnerabilities.Add(new Vulnerability(tipo, codigo, risco, lineNumbers));
                }
            }
        }
    }

    static bool ContainsDangerousInput(BinaryExpressionSyntax expression, SyntaxNode root)
    {
        // Check if the binary expression contains any potentially dangerous inputs
        // Specifically, check if it contains a variable that invokes Request.QueryString
        // and if that variable is not passed through Server.HtmlEncode

        var variables = expression.DescendantNodes().OfType<IdentifierNameSyntax>();
        foreach (var variable in variables)
        {
            // Check if the variable is invoking Request.QueryString
            if (variable.Identifier.Text == "QueryString" &&
                variable.Ancestors().OfType<MemberAccessExpressionSyntax>().Any(access =>
                    access.Name.Identifier.Text == "Request" &&
                    access.Expression is IdentifierNameSyntax identifier &&
                    identifier.Identifier.Text == "Request"))
            {
                // Check if this variable is passed to Server.HtmlEncode
                var variableSymbol = ModelExtensions.GetSymbolInfo(root.GetSemanticModel().GetTypeInfo(variable)).Symbol;
                var usages = root.DescendantNodes().OfType<InvocationExpressionSyntax>()
                    .Where(invocation =>
                        invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                        memberAccess.Name.Identifier.Text == "HtmlEncode" &&
                        memberAccess.Expression is IdentifierNameSyntax identifier &&
                        identifier.Identifier.Text == "Server" &&
                        invocation.ArgumentList.Arguments.Any(arg =>
                            arg.Expression is IdentifierNameSyntax argIdentifier &&
                            ModelExtensions.GetSymbolInfo(root.GetSemanticModel().GetTypeInfo(argIdentifier)).Symbol == variableSymbol));

                if (!usages.Any())
                {
                    // The variable invoking Request.QueryString is not passed to Server.HtmlEncode
                    return true;
                }
            }
        }

        return false;
    }


    static bool IsUserInput(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            var text = memberAccess.ToString();
            return text.StartsWith("Request.Form") ||
                   text.StartsWith("Request.QueryString") ||
                   text.StartsWith("Request.Params");
        }

        return false;
    }
    

    static NivelRisco DetermineXSSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isCSRFRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineCSRFRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isOpenRedirectRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineOpenRedirectAtack(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isHTTPSEnforcementRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineHTTPSEnforcement(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isCORSRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineCORSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isEncryptionRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineEncryptionRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isSSRFRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineSSRFRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isTLSRelated(SyntaxNode node)
    {
        return true;
    }
    static NivelRisco DetermineTLSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    private static bool isDoSRelated(SyntaxNode node)
    {
        return true;
    }
    private static NivelRisco DetermineDoSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

}