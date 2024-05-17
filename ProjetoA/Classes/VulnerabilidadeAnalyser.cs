using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

internal enum NivelRisco
{
    Alto,
    Medio,
    Baixo
}

internal class Vulnerability
{
    public string Tipo { get; }
    public string Codigo { get; }
    public List<int> Linhas { get; }
    public NivelRisco Risco { get; }

    public Vulnerability(string tipo, string codigo, NivelRisco risco, List<int> linhas)
    {
        Tipo = tipo;
        Codigo = codigo;
        Risco = risco;
        Linhas = linhas;
    }
}

internal class VulnerabilityAnalyzer
{
    private static List<Vulnerability> _vulnerabilities;

    public static List<Vulnerability> AnalizarVulnerabilidades(SyntaxNode root)
    {
        _vulnerabilities = new List<Vulnerability>();

        DetectSqlInjection(root);

        return _vulnerabilities;
    }

    public static void DetectSqlInjection(SyntaxNode root)
    {
        var type = "SQL Injection";

        // Find all invocations in the syntax tree
        var suspiciousNodes = root.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(node => IsSqlRelated(node));

        foreach (var node in suspiciousNodes)
        {
            var riskLevel = DetermineSqlInjectionRisk(node);
            var lineSpan = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
            var vulnerability = new Vulnerability(type, node.ToString(), riskLevel, new List<int> { lineSpan });

            _vulnerabilities.Add(vulnerability);
        }
    }

    private static bool IsSqlRelated(InvocationExpressionSyntax node)
    {
        // Check if the node contains SQL-related method names
        var sqlMethodNames = new List<string>
        {
            "SqlCommand",
            "SqlDataAdapter",
            "SqlConnection",
            "SqlDataReader",
            "SqlDataSource",
            "ExecuteNonQuery",
            "ExecuteReader",
            "ExecuteScalar",
            "ExecuteDbDataReader"
        };

        foreach (var methodName in sqlMethodNames)
        {
            if (node.ToString().Contains(methodName))
            {
                return true;
            }
        }

        return false;
    }

    private static NivelRisco DetermineSqlInjectionRisk(InvocationExpressionSyntax node)
    {
        // Analisar os argumentos passados para o método SQL
        var argumentList = node.ArgumentList.Arguments;
        foreach (var argument in argumentList)
        {
            var argumentExpression = argument.Expression;

            // Verificar se o argumento é uma string literal
            if (argumentExpression is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                // Verificar se a string literal contém concatenação
                if (literal.Token.ValueText.Contains("\" +") || literal.Token.ValueText.Contains("+ \""))
                {
                    return NivelRisco.Alto;
                }
            }

            // Verificar se o argumento é uma variável ou retorno de método (potencialmente inseguro)
            if (argumentExpression is IdentifierNameSyntax || argumentExpression is MemberAccessExpressionSyntax)
            {
                // Análise adicional pode ser feita aqui para verificar se o identificador vem de input do usuário
                // Exemplo: verificar se a variável está relacionada a um campo de entrada de usuário
                return NivelRisco.Medio;
            }
        }

        // Se nenhum risco direto for encontrado, classificar como risco baixo
        return NivelRisco.Baixo;
    }
}
