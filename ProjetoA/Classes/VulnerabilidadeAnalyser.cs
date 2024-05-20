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
    Baixo,
    Medio,
    Alto
}

public static class VulnerabilidadeAnalyzer
{
    static List<Vulnerability> Vulnerabilidades = new List<Vulnerability>();


    public static List<Vulnerability> AnalisarVulnerabilidades(SyntaxNode root)
    {
        Vulnerabilidades = new List<Vulnerability>();

        var type = "SQL Injection";

        foreach (var node in root.DescendantNodes())
        {
            if (isSQLRelated(node))
            {
                var riskLevel = DetermineSqlInjectionRisk(node);
                var lineSpan = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                var vulnerability = new Vulnerability(type, node.ToString(), riskLevel, new List<int> { lineSpan });
                Vulnerabilidades.Add(vulnerability);
            }
        }

        return Vulnerabilidades;
    }

    private static bool isSQLRelated(SyntaxNode node)
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
        else if (node is VariableDeclarationSyntax variableDeclaration)
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

        /*else if (node is UsingStatementSyntax usingStatement)
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
        }*/

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
        /*else if (node is UsingStatementSyntax usingStatement)
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
        }*/
        else if (node is VariableDeclarationSyntax variableDeclaration)
        {
            foreach (var variable in variableDeclaration.Variables)
            {
                if (variable.Initializer?.Value is ObjectCreationExpressionSyntax objectCreation)
                {
                    foreach (var argument in objectCreation.ArgumentList.Arguments)
                    {
                        if (argument.Expression is BinaryExpressionSyntax binaryExpression &&
                            (binaryExpression.Left is LiteralExpressionSyntax leftLiteral && leftLiteral.IsKind(SyntaxKind.StringLiteralExpression) ||
                             binaryExpression.Right is LiteralExpressionSyntax rightLiteral && rightLiteral.IsKind(SyntaxKind.StringLiteralExpression)))
                        {
                            riskLevel = NivelRisco.Alto;
                            break;
                        }
                        else if (argument.Expression is IdentifierNameSyntax identifierName)
                        {
                            // Verifique se o IdentifierName aponta para uma variável string no mesmo escopo
                            var variableSymbol = semanticModel.GetSymbolInfo(identifierName).Symbol as ILocalSymbol;
                            if (variableSymbol != null && variableSymbol.Type.SpecialType == SpecialType.System_String)
                            {
                                // Verificar se o valor da variável é uma string concatenada
                                var variableDeclarationNode = variableSymbol.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
                                if (variableDeclarationNode?.Initializer?.Value is BinaryExpressionSyntax binaryInitializer &&
                                    (binaryInitializer.Left is LiteralExpressionSyntax || binaryInitializer.Right is LiteralExpressionSyntax))
                                {
                                    riskLevel = NivelRisco.Alto;
                                    break;
                                }
                                else
                                {
                                    riskLevel = NivelRisco.Medio;
                                    break;
                                }
                            }
                        }
                    }
                }
                if (riskLevel != NivelRisco.Medio)
                    break; // Se o risco for alto, não precisamos verificar outras variáveis, podemos sair do loop.
            }
        }

        return riskLevel;

    }

    private static bool isDoSRelated(SyntaxNode node)
    {
        return true;
    }
    private static NivelRisco DetermineDoSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isXSSRelated(SyntaxNode node)
    {
        return true;
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
        return true ;
    }
    static NivelRisco DetermineEncryptionRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isSSRFRelated(SyntaxNode node)
    {
        return true ;
    }
    static NivelRisco DetermineSSRFRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

    static bool isTLSRelated(SyntaxNode node)
    {
        return true ;
    }
    static NivelRisco DetermineTLSRisk(SyntaxNode node)
    {
        return NivelRisco.Alto;
    }

}