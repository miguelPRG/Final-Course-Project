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
    public static List<Vulnerability> AnalisarVulnerabilidades(SyntaxNode root)
    {
        var vulnerabilities = new List<Vulnerability>();

        // Analisar vulnerabilidades de XSS
        //var xssVulnerabilities = AnalyzeForXSS(root);
        //vulnerabilities.AddRange(xssVulnerabilities);

        // Analisar vulnerabilidades de SQL Injection
        var sqlVulnerabilities = AnalyzeSQLInjection(root);
        vulnerabilities.AddRange(sqlVulnerabilities);

        return vulnerabilities;
    }
    
    private static VariableDeclarationSyntax FindVariableDeclaration(IdentifierNameSyntax identifierName, SyntaxNode root)
    {
        // Find all variable declarations with the same identifier name
        var variableDeclarations = root.DescendantNodes()
            .OfType<VariableDeclarationSyntax>()
            .Where(v => v.Variables.Any(var => var.Identifier.Text == identifierName.Identifier.Text));

        // Traverse up the syntax tree to find the nearest variable declaration
        foreach (var variableDeclaration in variableDeclarations)
        {
            var node = variableDeclaration.Parent;
            while (node != null)
            {
                if (node is BlockSyntax || node is MethodDeclarationSyntax)
                {
                    return variableDeclaration;
                }
                node = node.Parent;
            }
        }

        return null;
    }


    private static List<Vulnerability> AnalyzeSQLInjection(SyntaxNode root)
    {
        var vulnerabilities = new List<Vulnerability>();

        var objectCreations = root.DescendantNodes()
            .OfType<ObjectCreationExpressionSyntax>();

        foreach (var objectCreation in objectCreations)
        {
            // Check if the object being created is a SqlCommand
            if (objectCreation.Type.ToString() == "SqlCommand")
            {
                var arguments = objectCreation.ArgumentList.Arguments;
                if (arguments.Count > 0)
                {
                    var firstArgument = arguments[0].Expression;
                    if (firstArgument is IdentifierNameSyntax identifierName)
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
                    else if (firstArgument is LiteralExpressionSyntax ||
                             firstArgument is InterpolatedStringExpressionSyntax)
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
                }
            }
        }

        return vulnerabilities;
    }

    static List<Vulnerability> AnalyzeForXSS(SyntaxNode root)
    {
        var vulnerabilities = new List<Vulnerability>();

        var assignments = root.DescendantNodes()
            .OfType<AssignmentExpressionSyntax>();

        foreach (var assignment in assignments)
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess &&
                memberAccess.Name.Identifier.Text == "Text")
            {
                if (assignment.Right is InvocationExpressionSyntax invocation &&
                    invocation.Expression is MemberAccessExpressionSyntax invocationMemberAccess &&
                    invocationMemberAccess.Name.Identifier.Text == "Form")
                {
                    var lineSpan = assignment.GetLocation().GetLineSpan();
                    var lines = new List<int> { lineSpan.StartLinePosition.Line + 1 };

                    vulnerabilities.Add(new Vulnerability(
                        "XSS",
                        assignment.ToString(),
                        NivelRisco.Alto,
                        lines
                    ));
                }
            }
        }

        return vulnerabilities;
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