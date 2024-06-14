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
            AnalyzeForInsecureRandomGeneration,
            AnalyzeForInsecureGenerationCookies
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

        // Obtém todas as atribuições que potencialmente utilizam dados de entrada do usuário
        var atribuicoes = root.DescendantNodes().OfType<AssignmentExpressionSyntax>()
            .Where(v => v.ToString().IndexOf("Request.QueryString", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        v.ToString().IndexOf("Request.Form", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        v.ToString().IndexOf("Request.Params", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        v.ToString().IndexOf(".Text", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        v.ToString().IndexOf("ViewBag", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        v.ToString().IndexOf("ViewData", StringComparison.OrdinalIgnoreCase) >= 0);

        // Para cada atribuição encontrada
        foreach (var a in atribuicoes)
        {
            // Se o lado direito da atribuição não contém "Encode"
            if (!a.Right.ToString().Contains("Encode"))
            {
                // Busca no escopo do nó
                var escopo = GetScopeLevel(a.Right).DescendantNodes()
                                    .OfType<VariableDeclaratorSyntax>()
                                    .Where(es => es.Initializer.ToString().Contains("Encode"));

                if (!escopo.Any())
                {
                    var parent = a.Right.Parent;

                    // Verifica os nós ancestrais
                    while (parent != null && !(parent is ClassDeclarationSyntax))
                    {
                        parent = parent.Parent;

                    }

                    if (parent != null)
                    {
                        escopo = parent.DescendantNodes()
                                    .OfType<VariableDeclaratorSyntax>()
                                    .Where(es => es.Initializer.ToString().Contains("Encode"));
                    }
                }


                // Se não encontrou nenhum uso de "Encode" no escopo ou nos ancestrais
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

        // Obtém todas as variáveis que utilizam BinaryFormatter
        var variaveis = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                            .Where(i => i.Initializer != null && i.Initializer.Value.ToString().Contains("BinaryFormatter"));

        // Para cada variável encontrada
        foreach (var v in variaveis)
        {
            var scope = GetScopeLevel(v);
            var invocacoes = scope.DescendantNodes().OfType<InvocationExpressionSyntax>()
                                     .Where(i => i.Expression.ToString().Contains(v.Identifier.Text + ".Deserialize"));

            if (!invocacoes.Any())
            {
                var parent = v.Parent;

                // Verifica os nós ancestrais
                while (parent != null && !(parent is ClassDeclarationSyntax))
                {
                    parent = parent.Parent;
                }

                if (parent != null)
                {
                    invocacoes = parent.DescendantNodes().OfType<InvocationExpressionSyntax>()
                                      .Where(i => i.Expression.ToString().Contains(v.Identifier.Text + ".Deserialize"));
                }
            }

            if (invocacoes.Any())
            {
                PrepararParaAdicionarVulnerabilidade(v, tipo, risco);
            }
        }
    }
    private static void AnalyzeLDAPInjection(SyntaxNode root)
    {
        var tipo = "LDAP Injection";
        var risco = NivelRisco.Alto;

        // Conjunto para rastrear nós verificados
        var verificados = new HashSet<SyntaxNode>();

        // Obtém todos os objetos que potencialmente utilizam dados de entrada do usuário para LDAP
        var objects = root.DescendantNodes()
                          .OfType<ObjectCreationExpressionSyntax>()
                          .Where(v => v.Type.ToString().Contains("Search"));

        // Para cada objeto encontrado
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

                    var variaveis = scope.DescendantNodes()
                                         .OfType<VariableDeclaratorSyntax>()
                                         .Where(v => v.Identifier.ToString() == identifier.Identifier.ToString() &&
                                                     IsStringConcatenated(v.Initializer.Value));

                    if (!variaveis.Any())
                    {
                        var parent = arg.Parent;

                        // Verifica os nós ancestrais
                        while (parent != null && !(parent is ClassDeclarationSyntax))
                        {
                            parent = parent.Parent;
                        }

                        if (parent != null)
                        {
                            variaveis = parent.DescendantNodes()
                                         .OfType<VariableDeclaratorSyntax>()
                                         .Where(v => v.Identifier.ToString() == identifier.Identifier.ToString() &&
                                                     IsStringConcatenated(v.Initializer.Value));
                        }

                    }

                    if (variaveis.Any())
                    {
                        PrepararParaAdicionarVulnerabilidade(obj, tipo, risco);
                    }
                }
            }
        }
    }
    private static void AnalyzeForInsecureEncryption(SyntaxNode root)
    {
        var tipo = "Criptografia Insegura";
        var risco = NivelRisco.Alto;

        var cripto = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                         .Where(o => o.Initializer != null && (
                             o.Initializer.ToString().Contains("DES") ||
                             o.Initializer.ToString().Contains("DSA") ||
                             o.Initializer.ToString().Contains("SHA1") ||
                             o.Initializer.ToString().Contains("RC4") ||
                             o.Initializer.ToString().Contains("MD5") ||
                             o.Initializer.ToString().Contains("TripleDESCryptoServiceProvider") ||
                             o.Initializer.ToString().Contains("Blowfish") ||
                             o.Initializer.ToString().Contains("AesCryptoServiceProvider")));

        if (!cripto.Any())
        {
            return;
        }

        List<Task> tasks = new List<Task>();

        foreach (var c in cripto)
        {
            if (c.Initializer.ToString().Contains("AesCryptoServiceProvider"))
            {
                AnalyzeAesCryptoServiceProvider(c, tipo, risco);
            }
            else
            {
                PrepararParaAdicionarVulnerabilidade(c, tipo, risco);
            }
        }
    }
    private static void AnalyzeAesCryptoServiceProvider(VariableDeclaratorSyntax c, string tipo, NivelRisco risco)
    {
        var scope = GetScopeLevel(c);

        var atribuicoes = scope.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                               .Where(v =>
                                   (v.Left.ToString().Contains(c.Identifier.ToString() + ".Mode") && v.Right.ToString().Contains("CipherMode.CBC")) ||
                                   (v.Left.ToString().Contains(c.Identifier.ToString() + ".Padding") && v.Right.ToString().Contains("PaddingMode.PKCS7")) ||
                                   (v.Left.ToString().Contains(c.Identifier.ToString() + ".KeySize") && int.Parse(v.Right.ToString()) < 256) ||
                                   (v.Left.ToString().Contains(c.Identifier.ToString() + ".BlockSize") && int.Parse(v.Right.ToString()) < 256)
                               );

        if (!atribuicoes.Any())
        {
            var parent = c.Parent;

            while (parent != null && !(parent is ClassDeclarationSyntax))
            {
                parent = parent.Parent;
            }

            if (parent != null)
            {
                atribuicoes = parent.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                               .Where(v =>
                                   (v.Left.ToString().Contains(c.Identifier.ToString() + ".Mode") && v.Right.ToString().Contains("CipherMode.CBC")) ||
                                   (v.Left.ToString().Contains(c.Identifier.ToString() + ".Padding") && v.Right.ToString().Contains("PaddingMode.PKCS7")) ||
                                   (v.Left.ToString().Contains(c.Identifier.ToString() + ".KeySize") && int.Parse(v.Right.ToString()) < 256) ||
                                   (v.Left.ToString().Contains(c.Identifier.ToString() + ".BlockSize") && int.Parse(v.Right.ToString()) < 256)
                               );
            }
        }

        foreach (var a in atribuicoes)
        {
            PrepararParaAdicionarVulnerabilidade(a, tipo, risco);
        }
    }
    private static void AnalyzeForInsecureRandomGeneration(SyntaxNode root)
    {
        var tipo = "Geração Aleatória Insegura";
        var risco = NivelRisco.Alto;

        var random = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>()
                         .Where(o => o.Type.ToString() == "Random");

        foreach (var r in random)
        {
            PrepararParaAdicionarVulnerabilidade(r.Parent.Parent, tipo, risco);
        }
    }
    private static void AnalyzeForInsecureGenerationCookies(SyntaxNode root)
    {
        var tipo = "Geração Insegura de Cookies";
        var risco = NivelRisco.Alto;

        var objetos = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>()
                                 .Where(o => o.Type.ToString() == "CookiePolicyOptions");

        foreach(var obj in objetos)
        {
            var seguro = obj.DescendantNodes().OfType<InitializerExpressionSyntax>()
            .Any(i =>
                   i.Expressions.ToString()
                   .Contains("MinimumSameSitePolicy = SameSiteMode.Strict") &&
                   i.Expressions.ToString()
                   .Contains("HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always") &&
                   i.Expressions.ToString()
                   .Contains("Secure = CookieSecurePolicy.Always"));

            if (!seguro)
            {
                PrepararParaAdicionarVulnerabilidade(obj, tipo, risco);
            }
        }

    }
}