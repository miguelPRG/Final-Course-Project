using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

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
    private static List<Vulnerability> vulnerabilities = new List<Vulnerability>();

    private delegate void Analise(SyntaxNode root);

    public static async Task<List<Vulnerability>> AnalisarVulnerabilidades(SyntaxNode root)
    {
        vulnerabilities.Clear();

        var analises = new Analise[]
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
        await Task.WhenAll(tasks);

        return vulnerabilities;
    }

    private static void PrepararParaAdicionarVulnerabilidade(SyntaxNode node, string tipo, NivelRisco risco)
    {
        var linha = node.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
        var codigo = node.ToString().Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? node.ToString();

        AdicionarVulnerabilidade(tipo, codigo, risco, linha);
    }

    private static void AdicionarVulnerabilidade(string tipo, string codigo, NivelRisco risco, int linha)
    {
        var index = vulnerabilities.FindIndex(v => (v.Codigo == codigo || v.Linhas.Contains(linha)) && v.Tipo == tipo);

        lock (vulnerabilities)
        {
            if (index > -1)
            {
                vulnerabilities[index].Linhas.Add(linha);
            }
            else
            {
                vulnerabilities.Add(new Vulnerability(tipo, codigo, risco, new HashSet<int> { linha }));
            }
        }
    }

    private static SyntaxNode GetScopeLevel(SyntaxNode node)
    {
        while (node != null && !(node is MethodDeclarationSyntax || node is ClassDeclarationSyntax || node is BlockSyntax))
        {
            node = node.Parent;
        }
        return node;
    }

    private static bool IsStringConcatenated(ExpressionSyntax expression)
    {
        if (expression is BinaryExpressionSyntax binaryExpression && binaryExpression.IsKind(SyntaxKind.AddExpression))
        {
            return IsStringLiteral(binaryExpression.Left) || IsStringLiteral(binaryExpression.Right) || IsStringConcatenated(binaryExpression.Left) || IsStringConcatenated(binaryExpression.Right);
        }
        return expression is InterpolatedStringExpressionSyntax;
    }

    private static bool IsStringLiteral(ExpressionSyntax expression) => expression is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression);

    private static void AnalyzeForSQLInjection(SyntaxNode root)
    {
        var tipo = "SQL Injection";
        var risco = NivelRisco.Alto;

        var sqlKeywords = new[] { "select", "from", "where", "values", "update", "set", "delete", "create", "alter", "drop", "join", "group by", "having", "order by", "distinct" };

        var expressions = root.DescendantNodes().OfType<ExpressionSyntax>().Where(IsStringConcatenated);

        foreach (var exp in expressions)
        {
            if (sqlKeywords.Count(keyword => exp.ToString().IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0) >= 2)
            {
                PrepararParaAdicionarVulnerabilidade(exp, tipo, risco);
            }
        }
    }
    private static void AnalyzeForXSS(SyntaxNode root)
    {
        var tipo = "XSS";
        var risco = NivelRisco.Alto;

        var atribuicoes = root.DescendantNodes().OfType<AssignmentExpressionSyntax>()
            .Where(v => v.ToString().IndexOf("Request.QueryString", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        v.ToString().IndexOf("Request.Form", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        v.ToString().IndexOf("Request.Params", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        v.ToString().IndexOf(".Text", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        v.ToString().IndexOf("ViewBag", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        v.ToString().IndexOf("ViewData", StringComparison.OrdinalIgnoreCase) >= 0);

        foreach (var a in atribuicoes)
        {
            if (!a.Right.ToString().Contains("Encode"))
            {
                var escopo = GetScopeLevel(a.Right).DescendantNodes().OfType<VariableDeclaratorSyntax>()
                          .Where(es => es.Initializer.ToString().Contains("Encode"));

                if (!escopo.Any())
                {
                    var analyzedNodes = new HashSet<SyntaxNode>();


                    var parent = a.Right.Parent;

                    while (parent != null)
                    {
                        if (!analyzedNodes.Contains(parent))
                        {
                            escopo = GetScopeLevel(parent).DescendantNodes().OfType<VariableDeclaratorSyntax>()
                              .Where(es => es.Initializer.ToString().Contains("Encode"));

                            analyzedNodes.Add(parent);

                            if (escopo.Any())
                            {
                                break;
                            }
                        }

                        parent = parent.Parent;
                    }
                }

                if (!escopo.Any() && !a.Right.DescendantNodes().OfType<VariableDeclaratorSyntax>().Any(es => es.Initializer.ToString().Contains("Encode")))
                {
                    PrepararParaAdicionarVulnerabilidade(a, tipo, risco);
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

            if (!invocacoes.Any())
            {
                var analyzedNodes = new HashSet<SyntaxNode>();


                var parent = v.Parent;

                while (parent != null)
                {
                    if (!analyzedNodes.Contains(parent))
                    {
                        invocacoes = parent.DescendantNodes().OfType<InvocationExpressionSyntax>()
                                  .Where(i => i.Expression.ToString().Contains(v.Identifier.Text + ".Deserialize"));

                        analyzedNodes.Add(parent);

                        if (invocacoes.Any())
                        {
                            break;
                        }
                    }

                    parent = parent.Parent;
                }
            }

            if(invocacoes.Any())
            {
                PrepararParaAdicionarVulnerabilidade(v, tipo, risco);
            }
        }
    }
    private static void AnalyzeLDAPInjection(SyntaxNode root)
    {
        var tipo = "LDAP Injection";
        var risco = NivelRisco.Alto;

        var objects = root.DescendantNodes()
                          .OfType<ObjectCreationExpressionSyntax>()
                          .Where(v => v.Type.ToString().Contains("Search"));

        foreach (var obj in objects)
        {
            foreach (var arg in obj.ArgumentList.Arguments)
            {
                if (IsStringConcatenated(arg.Expression))
                {
                    PrepararParaAdicionarVulnerabilidade(arg, tipo, risco);
                }

                else if (arg.Expression is IdentifierNameSyntax identifier)
                {
                    var scope = GetScopeLevel(arg);
                    /**/
                }
            }
        }
    }
    private static void AnalyzeForInsecureEncryption(SyntaxNode root)
    {
        var tipo = "Criptografia Insegura";
        var risco = NivelRisco.Alto;

        try
        {
            var cripto = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                        .Where(o => o.Initializer.ToString().Contains("DES") ||
                                    o.Initializer.ToString().Contains("RC4") ||
                                    o.Initializer.ToString().Contains("MD5"));

            foreach (var c in cripto)
            {
                PrepararParaAdicionarVulnerabilidade(c, tipo, risco);
            }
        }

        catch (NullReferenceException)
        {
            return;
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
