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
    private class SQLRelatedSyntaxWalker : CSharpSyntaxWalker
    {
        public List<SyntaxNode> SQLNodes { get; } = new List<SyntaxNode>();

        public override void VisitInvocationExpression(InvocationExpressionSyntax node)
        {
            if (isSQLRelated(node))
            {
                SQLNodes.Add(node);
            }
            base.VisitInvocationExpression(node);
        }

        public override void VisitObjectCreationExpression(ObjectCreationExpressionSyntax node)
        {
            if (isSQLRelated(node))
            {
                SQLNodes.Add(node);
            }
            base.VisitObjectCreationExpression(node);
        }
    }

    private class XSSRelatedSyntaxWalker : CSharpSyntaxWalker
    {
        public List<SyntaxNode> XSSNodes { get; } = new List<SyntaxNode>();

        public override void VisitMemberAccessExpression(MemberAccessExpressionSyntax node)
        {
            if (isXSSRelated(node))
            {
                XSSNodes.Add(node);
            }

            base.VisitMemberAccessExpression(node);
        }

    }


    public static List<Vulnerability> AnalisarVulnerabilidades(SyntaxNode root)
    {
        var vulnerabilities = new List<Vulnerability>();

        var visitorSQL = new SQLRelatedSyntaxWalker();
        visitorSQL.Visit(root);

        var visitorXSS = new XSSRelatedSyntaxWalker();

        /*foreach (var node in visitorSQL.SQLNodes)
        {
            var riskLevel = NivelRisco.Alto;
            var lineSpan = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
            var vulnerability = new Vulnerability("SQL Injection", node.ToString(), riskLevel, new List<int> { lineSpan });
            vulnerabilities.Add(vulnerability);
        }*/

        foreach (var node in visitorXSS.XSSNodes)
        {
            var riskLevel = NivelRisco.Alto;
            var lineSpan = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
            var vulnerability = new Vulnerability("XSS Atack", node.ToString(), riskLevel, new List<int> { lineSpan });
            vulnerabilities.Add(vulnerability);
        }

        return vulnerabilities;
    }
    private static bool isSQLRelated(SyntaxNode node)
    {
        if (node is InvocationExpressionSyntax invocation)
        {
            var sqlMethodNames = new List<string>
            {
                "ExecuteNonQuery",
                "ExecuteReader",
                "ExecuteScalar",
                "ExecuteDbDataReader"
            };

            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;
                if (sqlMethodNames.Contains(methodName))
                {
                    return true;
                }
            }
        }
        else if (node is ObjectCreationExpressionSyntax objectExpression)
        {
            var sqlTypes = new List<string>
            {
                "SqlCommand",
                "SqlDataAdapter",
                "SqlConnection",
                "SqlDataReader",
                "SqlDataSource"
            };

            var typeName = objectExpression.Type.ToString();
            if (sqlTypes.Contains(typeName))
            {
                return true;
            }
        }

        return false;
    }
    /*private static NivelRisco DetermineSqlInjectionRisk(SyntaxNode node)
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

}*/

    public static bool isXSSRelated(SyntaxNode node)
    {
        if (node is InvocationExpressionSyntax invocation)
        {
            var xssMethodNames = new List<string>
                {
                    "Write",
                    "WriteLine",
                    "Append"
                    // Adicione aqui outros métodos que possam ser usados para inserir conteúdo não escapado em uma página da web
                };

            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;
                if (xssMethodNames.Contains(methodName))
                {
                    return true;
                }
            }
        }
        else if (node is ObjectCreationExpressionSyntax objectExpression)
        {
            var xssTypes = new List<string>
                {
                    "StringBuilder"
                    // Adicione aqui outros tipos que possam ser usados para construir conteúdo não escapado em uma página da web
                };

            var typeName = objectExpression.Type.ToString();
            if (xssTypes.Contains(typeName))
            {
                return true;
            }
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
