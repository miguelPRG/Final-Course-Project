using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

//Site para procurrar referências: https://docs.fluidattacks.com/

public class Vulnerability
{
    public string Tipo { get; set; }
    public string Codigo { get; set; }
    public NivelRisco Risco { get; set; }
    public HashSet<int> Linhas { get; set; }

    public Vulnerability(string tipo, string codigo, NivelRisco risco, HashSet<int> linhas)
    {
        Tipo = tipo;
        Codigo = codigo;
        Risco = risco;
        Linhas = linhas;
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
    private static List<Vulnerability> vulnerabilities;

    delegate void Analise(SyntaxNode root);

    public async static Task<List<Vulnerability>> AnalisarVulnerabilidades(SyntaxNode root)
    {
        vulnerabilities = new List<Vulnerability>();

        Analise[] analises = new Analise[]
        {
            AnalyzeForSQLInjection,
            AnalyzeForXSS,
            AnalyzeForCSRF,
            AnalyzeForInsecureDeserialization,
            AnalyzeLDAPInjection,
            AnalyzeForInsecureEncryption,
            AnalyzeForSensitiveInformationSending
        };

        var tasks = analises.Select(a => Task.Run(() => a(root))).ToArray();
        Task.WaitAll(tasks);

        return await Task.FromResult(vulnerabilities);
    }

    private static void PrepararParaAdicionarVulnerabilidade(SyntaxNode node, string tipo, NivelRisco risco)
    {
        char[] mudanca = new char[] { '\n', '\r' };
        int linha = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
        int index = node.ToString().IndexOfAny(mudanca);

        string codigo;

        try
        {
            codigo = node.ToString().Substring(0, index);
        }
        catch (ArgumentOutOfRangeException)
        {
            codigo = node.ToString();
        }

        AdicionarVulnerabilidade(tipo, codigo, risco, linha);
    }

    private static void AdicionarVulnerabilidade(string tipo, string codigo, NivelRisco risco, int linha)
    {
        var index = vulnerabilities.FindIndex(v => (v.Codigo == codigo || v.Linhas.Contains(linha)) && v.Tipo == tipo);

        lock (vulnerabilities)
        {
            if (index > -1)
            {
                // Adicionar a nova linha à lista de linhas da vulnerabilidade existente
                vulnerabilities[index].Linhas.Add(linha);
            }
            else
            {
                // Adicionar nova vulnerabilidade
                var lineNumbers = new HashSet<int> { linha };
                vulnerabilities.Add(new Vulnerability(tipo, codigo, risco, lineNumbers));
            }
        }
    }

    private static SyntaxNode GetScopeLevel(SyntaxNode node)
    {
        while (node != null)
        {
            if (node is MethodDeclarationSyntax || node is ClassDeclarationSyntax || node is BlockSyntax)
            {
                return node;
            }
            node = node.Parent;
        }
        return null;
    }

    private static bool IsStringConcatenated(ExpressionSyntax expression)
    {
        if (expression is BinaryExpressionSyntax binaryExpression)
        {
            if (binaryExpression.IsKind(SyntaxKind.AddExpression))
            {
                if (binaryExpression.Left is LiteralExpressionSyntax leftLiteral && leftLiteral.IsKind(SyntaxKind.StringLiteralExpression))
                    return true;
                if (binaryExpression.Right is LiteralExpressionSyntax rightLiteral && rightLiteral.IsKind(SyntaxKind.StringLiteralExpression))
                    return true;
                if (IsStringConcatenated(binaryExpression.Left) || IsStringConcatenated(binaryExpression.Right))
                    return true;
            }
        }
        else if (expression is InterpolatedStringExpressionSyntax)
        {
            return true;
        }
        return false;
    }

    private static void AnalyzeForSQLInjection(SyntaxNode root)
    {
        var tipo = "SQL Injection";
        var risco = NivelRisco.Alto;

        string[] sqlKeywords = new string[]
        {
            "select", "from", "where", "values", "update", "set", "delete",
            "create", "alter", "drop", "join", "group by", "having",
            "order by", "distinct"
        };

        var expressions = root.DescendantNodes()
                              .OfType<ExpressionSyntax>()
                              .Where(node => IsStringConcatenated(node));

        foreach (var exp in expressions)
        {
            string expressionText = exp.ToString();
            int keywordCount = sqlKeywords.Count(keyword => expressionText.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0);

            if (keywordCount >= 2)
            {
                PrepararParaAdicionarVulnerabilidade(exp, tipo, risco);
            }
        }

        var interpolatedStrings = root.DescendantNodes()
                                      .OfType<InterpolatedStringExpressionSyntax>();

        foreach (var str in interpolatedStrings)
        {
            int keywordCount = sqlKeywords.Count(keyword => str.ToString().IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0);

            if (keywordCount >= 2)
            {
                PrepararParaAdicionarVulnerabilidade(str, tipo, risco);
            }
        }
    }
    private static void AnalyzeForXSS(SyntaxNode root)
    {
        var tipo = "XSS";
        var risco = NivelRisco.Alto;

        var variaveis = root.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                            .Where(v => v.Right != null &&
                                       (v.Right.ToString().Contains("Request.QueryString") ||
                                        v.Right.ToString().Contains("Request.Form") ||
                                        v.Right.ToString().Contains("Request.Params") ||
                                        v.Right.ToString().Contains(".Text")));

        var metodos = root.DescendantNodes().OfType<MethodDeclarationSyntax>()
                          .Where(m => m.AttributeLists.ToString().Contains("[HttpPost]"));

        if (!variaveis.Any() && !metodos.Any())
        {
            return;
        }

        foreach (var v in variaveis)
        {
            PrepararParaAdicionarVulnerabilidade(v.Parent, tipo, risco);
        }

        foreach (var m in metodos)
        {
            var parametros = m.ParameterList.Parameters
                                .Where(p => p.ToString().Contains("string"));

            foreach (var p in parametros)
            {
                var vulnerabilidades = m.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                                        .Where(v => v.Right.ToString() == p.Identifier.ToString());

                foreach (var v in vulnerabilidades)
                {
                    PrepararParaAdicionarVulnerabilidade(v.Parent, tipo, risco);
                }
            }
        }
    }
    private static void AnalyzeForCSRF(SyntaxNode root)
    {
        var tipo = "CSRF";
        var risco = NivelRisco.Alto;

        var metodos = root.DescendantNodes().OfType<MethodDeclarationSyntax>()
                          .Where(m => m.AttributeLists.ToString().Contains("[HttpPost]") &&
                                      !m.AttributeLists.ToString().Contains("[ValidateAntiForgeryToken]"));

        foreach (var m in metodos)
        {
            PrepararParaAdicionarVulnerabilidade(m, tipo, risco);
        }
    }
    private static void AnalyzeForInsecureDeserialization(SyntaxNode root)
    {
        var tipo = "Deserialização Insegura";
        var risco = NivelRisco.Alto;

        var variaveis = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                            .Where(i => i.Initializer != null && i.Initializer.Value.ToString().Contains("BinaryFormatter"));

        foreach (var v in variaveis)
        {
            var scope = GetScopeLevel(v);

            var invocacoes = scope.DescendantNodes().OfType<InvocationExpressionSyntax>()
                                  .Where(i => i.Expression.ToString().Contains(v.Identifier.Text + ".Deserialize"));

            foreach (var i in invocacoes)
            {
                PrepararParaAdicionarVulnerabilidade(i.Parent, tipo, risco);
            }
        }
    }
    private static void AnalyzeLDAPInjection(SyntaxNode root)
    {
        var tipo = "LDAP Injection";
        var risco = NivelRisco.Alto;

        var objects = root.DescendantNodes()
                          .OfType<ObjectCreationExpressionSyntax>()
                          .Where(v => v.Type.ToString() == "SearchRequest");

        foreach (var obj in objects)
        {
            var arguments = obj.ArgumentList.Arguments;

            foreach (var arg in arguments)
            {
                if (IsStringConcatenated(arg.Expression))
                {
                    PrepararParaAdicionarVulnerabilidade(arg, tipo, risco);
                }
                else if (arg.Expression is IdentifierNameSyntax identifier)
                {
                    var variableName = identifier.Identifier.Text;
                    var scopeLevel = GetScopeLevel(arg);

                    var variableDeclarations = scopeLevel.DescendantNodes()
                                                         .OfType<VariableDeclaratorSyntax>()
                                                         .Where(v => v.Identifier.Text == variableName);

                    foreach (var variableDeclaration in variableDeclarations)
                    {
                        var initializer = variableDeclaration.Initializer?.Value;
                        if (initializer != null && IsStringConcatenated(initializer))
                        {
                            PrepararParaAdicionarVulnerabilidade(initializer, tipo, risco);
                        }
                    }
                }
            }
        }
    }
    private static void AnalyzeForInsecureEncryption(SyntaxNode root)
    {
        var tipo = "Criptografia Insegura";
        var risco = NivelRisco.Alto;

        var cripto = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>()
                         .Where(o => o.Type.ToString().Contains("DES") ||
                                     o.Type.ToString().Contains("RC4") ||
                                     o.Type.ToString().Contains("MD5"));

        foreach (var c in cripto)
        {
            PrepararParaAdicionarVulnerabilidade(c, tipo, risco);
        }
    }
    private static void AnalyzeForSensitiveInformationSending(SyntaxNode root)
    {
        var tipo = "Envio de Informações Sensíveis";
        var risco = NivelRisco.Alto;

        var metodos = root.DescendantNodes().OfType<MethodDeclarationSyntax>()
                          .Where(m => m.AttributeLists.ToString().Contains("[HttpPost]"));

        foreach (var m in metodos)
        {
            var retorno = m.DescendantNodes().OfType<ReturnStatementSyntax>()
                           .Where(r => r.Expression.ToString().ToLower().Contains("username") ||
                                       r.Expression.ToString().ToLower().Contains("password"));

            foreach (var r in retorno)
            {
                PrepararParaAdicionarVulnerabilidade(r, tipo, risco);
            }
        }
    }
}
