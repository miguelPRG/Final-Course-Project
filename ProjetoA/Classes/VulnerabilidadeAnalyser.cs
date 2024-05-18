using System;
using System.Collections.Generic;
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
    Baixo,
    Medio,
    Alto
}

public static class VulnerabilidadeAnalyzer
{
    static List<Vulnerability> Vulnerabilidades = new List<Vulnerability>();

    public static List<Vulnerability> AnalisarVulnerabilidades(SyntaxNode root)
    {
        var type = "SQL Injection";

        foreach (var node in root.DescendantNodes())
        {
            if (IsSqlRelated(node))
            {
                var riskLevel = DetermineSqlInjectionRisk(node);
                var lineSpan = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                var vulnerability = new Vulnerability(type, node.ToString(), riskLevel, new List<int> { lineSpan });
                Vulnerabilidades.Add(vulnerability);
            }
        }

        return Vulnerabilidades;
    }

    private static bool IsSqlRelated(SyntaxNode node)
    {
        // Check for SQL-related method invocations
        if (node is InvocationExpressionSyntax invocation)
        {
            var sqlMethodNames = new List<string>
            {
                "ExecuteNonQuery",
                "ExecuteReader",
                "ExecuteScalar",
                "ExecuteDbDataReader"
            };

            var memberAccess = invocation.Expression as MemberAccessExpressionSyntax;
            if (memberAccess != null)
            {
                var methodName = memberAccess.Name.Identifier.Text;
                if (sqlMethodNames.Contains(methodName))
                {
                    return true;
                }
            }
        }

        // Check for SQL-related variable declarations
        if (node is VariableDeclarationSyntax variableDeclaration)
        {
            var sqlTypes = new List<string>
            {
                "SqlCommand",
                "SqlDataAdapter",
                "SqlConnection",
                "SqlDataReader",
                "SqlDataSource"
            };

            var variableType = variableDeclaration.Type.ToString();
            if (sqlTypes.Contains(variableType))
            {
                return true;
            }
        }

        // Check for object creation inside using statements
        if (node is UsingStatementSyntax usingStatement)
        {
            var descendants = usingStatement.DescendantNodes();
            foreach (var descendant in descendants)
            {
                if (descendant is ObjectCreationExpressionSyntax objectCreation)
                {
                    var type = objectCreation.Type.ToString();
                    var sqlTypes = new List<string>
                    {
                        "SqlCommand",
                        "SqlDataAdapter",
                        "SqlConnection",
                        "SqlDataReader",
                        "SqlDataSource"
                    };

                    if (sqlTypes.Contains(type))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private static NivelRisco DetermineSqlInjectionRisk(SyntaxNode node)
    {
        NivelRisco riskLevel = NivelRisco.Baixo;

        if (node is InvocationExpressionSyntax invocation)
        {
            // Analyze the arguments passed to the SQL method
            var argumentList = invocation.ArgumentList.Arguments;
            foreach (var argument in argumentList)
            {
                var argumentExpression = argument.Expression;

                // Check if the argument is a string literal
                if (argumentExpression is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
                {
                    // Check if the string literal contains concatenation
                    if (literal.Token.ValueText.Contains("\" +") || literal.Token.ValueText.Contains("+ \""))
                    {
                        riskLevel = NivelRisco.Alto;
                    }
                }

                // Check if the argument is a variable or method return (potentially insecure)
                if (argumentExpression is IdentifierNameSyntax || argumentExpression is MemberAccessExpressionSyntax)
                {
                    // Additional analysis can be done here to check if the identifier comes from user input
                    // Example: check if the variable is related to a user input field
                    riskLevel = NivelRisco.Medio;
                }
            }
        }
        else if (node is UsingStatementSyntax usingStatement)
        {
            var descendants = usingStatement.DescendantNodes();
            foreach (var descendant in descendants)
            {
                if (descendant is VariableDeclaratorSyntax variableDeclaratorDesc && variableDeclaratorDesc.Initializer?.Value is ObjectCreationExpressionSyntax creationExpression)
                {
                    var argumentList = creationExpression.ArgumentList.Arguments;

                    foreach (var argument in argumentList)
                    {
                        var argumentExpression = argument.Expression;

                        // Check if the argument is a string literal with concatenation
                        if (argumentExpression is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
                        {
                            if (literal.Token.ValueText.Contains("\" +") || literal.Token.ValueText.Contains("+ \""))
                            {
                                riskLevel = NivelRisco.Alto;
                            }
                        }

                        // Check if the argument is a variable or method return (potentially insecure)
                        else if (argumentExpression is IdentifierNameSyntax || argumentExpression is MemberAccessExpressionSyntax)
                        {
                            riskLevel = NivelRisco.Medio;
                        }
                    }
                }
            }
        }
        else if (node is VariableDeclaratorSyntax variableDeclaratorDesc)
        {
            // Check if the variable's initializer is a string literal with concatenation
            if (variableDeclaratorDesc.Initializer?.Value is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                if (literal.Token.ValueText.Contains("\" +") || literal.Token.ValueText.Contains("+ \""))
                {
                    riskLevel = NivelRisco.Alto;
                }
            }
            else if (variableDeclaratorDesc.Initializer?.Value is IdentifierNameSyntax || variableDeclaratorDesc.Initializer?.Value is MemberAccessExpressionSyntax)
            {
                riskLevel = NivelRisco.Medio;
            }
        }

        return riskLevel;
    }

}
