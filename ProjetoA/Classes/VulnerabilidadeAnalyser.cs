using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Windows.Storage;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Shapes;

public class Vulnerability
{
    public string Tipo { get; set; }
    public string Codigo { get; set; }
    public NivelRisco Risco { get; set; }
    public HashSet<int> Linhas { get; set; }

    public Vulnerability(string type, string node, NivelRisco riskLevel, HashSet<int> lineNumbers)
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
    static char[] mudanca = new char[] { ';', '\n', '\r' };

    public static List<Vulnerability> AnalisarVulnerabilidades(SyntaxNode root)
    {
        vulnerabilities = new List<Vulnerability>();

        /*var compilation = CSharpCompilation.Create("MyCompilation")
                                            .AddReferences(MetadataReference.CreateFromFile(typeof(object).Assembly.Location))
                                            .AddSyntaxTrees(tree);*/

        //var semanticModel = compilation.GetSemanticModel(tree);

        // Analisar vulnerabilidades de XSS
        AnalyzeForInsecureDeserialization(root);

        // Analisar vulnerabilidades de SQL Injection
        //var sqlVulnerabilities = AnalyzeSQLInjection(root);
        //vulnerabilities.AddRange(sqlVulnerabilities);

        return vulnerabilities;
    }

    static SyntaxNode GetScope(SyntaxNode node)
    {
        // Obter o escopo em que o nó está (método, lambda, etc.)
        while (node != null && !(node is MethodDeclarationSyntax || node is LocalFunctionStatementSyntax || node is LambdaExpressionSyntax))
        {
            node = node.Parent;
        }
        return node;
    }

    static void AdicionarVulnerabilidade(string tipo, string codigo, NivelRisco risco, int linha)
    {
        object obj = new object();

        var index = vulnerabilities.IndexOf(
            vulnerabilities.FirstOrDefault(v => v.Codigo == codigo && v.Tipo == tipo));
                       

        lock (obj)
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

    static void AnalyzeForSQLInjection(SyntaxNode root)
    {
        var tipo = "SQL Injection";
        var risco = NivelRisco.Alto;

        string[] sqlReservedKeywords = new string[]
        {
            "select",
            "from",
            "where",
            "values",
            "update",
            "set",
            "delete",
            "create",
            "alter",
            "drop",
            "join",
            "group by",
            "having",
            "order by",
            "distinct",
        };

        var variables = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                            .Where(v => v.Initializer != null &&
                                        v.Initializer.Value is BinaryExpressionSyntax binaryExpression &&
                                        binaryExpression.IsKind(SyntaxKind.AddExpression));

        foreach (var variable in variables)
        {
            var binaryExpression = (BinaryExpressionSyntax)variable.Initializer.Value;

            string expressionText = binaryExpression.ToString();
            int keywordCount = 0;

            foreach (var keyword in sqlReservedKeywords)
            {
                if (expressionText.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    keywordCount++;
                }
            }

            if (keywordCount >= 2)
            {
                string codigo = variable.Parent.ToString();
                var linha = variable.Parent.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);
            }
        }
    }
    static void AnalyzeForXSS(SyntaxNode root)
    {
        var tipo = "XSS";
        var risco = NivelRisco.Alto; // Ajuste conforme necessário

        // Encontrar variáveis inicializadas com Request.QueryString, Request.Form, Request.Params
        var variaveis = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                            .Where(v => v.Initializer != null &&
                                        (v.Initializer.Value.ToString().Contains("Request.QueryString") ||
                                         v.Initializer.Value.ToString().Contains("Request.Form") ||
                                         v.Initializer.Value.ToString().Contains("Request.Params") ||
                                         v.Initializer.Value.ToString().Contains(".Text")));

        // Verificar se existe pelo menos uma variável encontrada
        if (!variaveis.Any())
        {
            return;
        }

        // Encontrar todas as chamadas para HttpUtility.HtmlEncode ou Server.HtmlEncode
        var codificacoes = root.DescendantNodes().OfType<InvocationExpressionSyntax>()
                            .Where(i => i.Expression.ToString().Contains("HttpUtility.HtmlEncode") ||
                                        i.Expression.ToString().Contains("Server.HtmlEncode"));

        // Verificar se cada variável encontrada é codificada antes de ser usada em uma saída HTML
        foreach (var v in variaveis)
        {
            bool isEncoded = false;

            foreach (var codificacao in codificacoes)
            {
                var scope = GetScope(codificacao);
                if (scope != null && scope.Contains(v))
                {
                    isEncoded = codificacao.ArgumentList.Arguments
                                .Any(arg => arg.ToString().Contains(v.Identifier.Text));
                    if (isEncoded) break;
                }
            }

            if (!isEncoded)
            {
                string codigo;
                int index = v.Parent.ToString().IndexOfAny(mudanca);

                try
                {
                    codigo = v.Parent.ToString().Substring(0, index);
                }
                catch (Exception)
                {
                    codigo = v.Parent.ToString();
                }

                var linha = v.Parent.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);
            }
        }
    }

    static void AnalyzeForCSRF(SyntaxNode root)
    {
        var tipo = "CSRF";
        var risco = NivelRisco.Alto;

        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();

        foreach(var m in methods)
        {
            var listaAtributos = m.AttributeLists;

            int httpPost = 0;
            int antiForgery = 0;

            foreach (var a in listaAtributos)
            {
                if(a.ToString() == "[HttpPost]")
                {
                    httpPost++;
                }

                else if(a.ToString() == "[ValidateAntiForgeryToken]")
                {
                    antiForgery++;
                }
            }

            if(httpPost > antiForgery)
            {
                string codigo;
                int index = m.ToString().IndexOfAny(mudanca);

                try
                {
                    codigo = m.ToString().Substring(0, index);
                }

                catch (ArgumentOutOfRangeException)
                {
                    codigo = m.ToString();
                }

                var linha = m.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);
            }
        }


    }
    static void AnalyzeForInsecureDeserialization(SyntaxNode root) 
    {
        var tipo = "Deserialização Insegura";
        var risco = NivelRisco.Alto;

        IEnumerable<VariableDeclaratorSyntax> variaveis;
        IEnumerable<InvocationExpressionSyntax> incovations;
        
        variaveis = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
        .Where(i => i.Initializer.ToString().Contains("BinaryFormatter"));

        foreach (var v in variaveis)
        {
            incovations = root.DescendantNodes().OfType<InvocationExpressionSyntax>()
                .Where(i => i.Expression.ToString().Contains(v.Identifier + ".Deserialize"));

            foreach (var i in incovations)
            {
                int linha = i.Parent.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                int index = i.Parent.ToString().IndexOfAny(mudanca);

                string codigo;

                try
                {
                    codigo = i.Parent.ToString().Substring(0, index);
                }

                catch (ArgumentOutOfRangeException)
                {
                    codigo = i.Parent.ToString();
                }

                AdicionarVulnerabilidade(tipo, codigo, risco, linha);
            }
       
        }
            
    }
    
    static void AnalyzeForInsecureRedirects(SyntaxNode root) { }
    static void AnalyzForNoSQLInjection(SyntaxNode root) { }
    static void AnalyzeForInsecureEncryption(SyntaxNode root) { }
    static void AnalyzeForLDAPInjection(SyntaxNode root) { }

}