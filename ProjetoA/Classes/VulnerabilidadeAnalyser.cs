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

    public static List<Vulnerability> AnalisarVulnerabilidades(SyntaxNode root)
    {
        vulnerabilities = new List<Vulnerability>();

        /*var compilation = CSharpCompilation.Create("MyCompilation")
                                            .AddReferences(MetadataReference.CreateFromFile(typeof(object).Assembly.Location))
                                            .AddSyntaxTrees(tree);*/

        //var semanticModel = compilation.GetSemanticModel(tree);

        // Analisar vulnerabilidades de XSS
        AnalyzeForSQLInjection(root);

        // Analisar vulnerabilidades de SQL Injection
        //var sqlVulnerabilities = AnalyzeSQLInjection(root);
        //vulnerabilities.AddRange(sqlVulnerabilities);

        return vulnerabilities; 
    }

    private static SyntaxNode GetScope(SyntaxNode node)
    {
        while (node != null && !(node is MethodDeclarationSyntax || node is ConstructorDeclarationSyntax || node is ClassDeclarationSyntax))
        {
            node = node.Parent;
        }
        return node;
    }

    static void PrepararParaAdiconarVulnerabilidade(SyntaxNode node,string tipo,NivelRisco risco)
    {
        char[] mudanca = new char[] { ';', '\n', '\r' };
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

        var expressions = root.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                            .Where(v => v.Right is BinaryExpressionSyntax binaryExpression &&
                                        binaryExpression.IsKind(SyntaxKind.AddExpression));

        foreach (var exp in expressions)
        {
            var binaryExpression = (BinaryExpressionSyntax)exp.Right;

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
                //var codigo = variable.ToString();
                //var linha = variable.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                PrepararParaAdiconarVulnerabilidade(exp, tipo, risco);

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
                PrepararParaAdiconarVulnerabilidade(v.Parent, tipo, risco);
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
                PrepararParaAdiconarVulnerabilidade(m, tipo, risco);
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
                PrepararParaAdiconarVulnerabilidade(i.Parent, tipo, risco);
            }
       
        }
            
    }
    static void AnalyzeForInsecureRedirects(SyntaxNode root) 
    {
        var tipo = "Deserialização Insegura";
        var risco = NivelRisco.Alto;

        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>()
                  .Where(m => m.Expression.ToString().Contains("Redirect"));

        foreach (var inv in invocations)
        {
            var argumentList = inv.ArgumentList.Arguments;
            if (argumentList.Count > 0)
            {
                var firstArgument = argumentList[0].ToString();

                // Verificar se o argumento é uma string literal
                if (firstArgument.StartsWith("\"") && firstArgument.EndsWith("\""))
                {
                    PrepararParaAdiconarVulnerabilidade(inv.Parent, tipo, risco);
                }
                
                else
                {
                    // Verificar se existe um if statement com Url.IsLocalUrl no mesmo escopo
                    var parentScope = GetScope(inv);
                    if (parentScope != null)
                    {
                        var ifStatements = parentScope.DescendantNodes().OfType<IfStatementSyntax>()
                            .Where(ifStmt => ifStmt.Condition.ToString().Contains($"Url.IsLocalUrl({firstArgument})"));

                        if (!ifStatements.Any())
                        {
                            PrepararParaAdiconarVulnerabilidade(inv.Parent, tipo, risco);
                        }
                    
                    }
                }
            }
        }

        // Exibir vulnerabilidades encontradas

    }

   static void AnalyzeForNoSQLInjection(SyntaxNode root)
   {
        var tipo = "NoSQL Injection";
        var risco = NivelRisco.Alto;

        // Procura por invocações de método
        var methodInvocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>(); 

        foreach (var invocation in methodInvocations)
        {
            var memberAccess = invocation.Expression as MemberAccessExpressionSyntax;

            if (memberAccess != null && memberAccess.Name.Identifier.Text == "Find")
            {
                var collectionName = memberAccess.Expression.ToString();

                // Verifica se o argumento para Find é construído de forma insegura
                var arguments = invocation.ArgumentList.Arguments;

                foreach (var argument in arguments)
                {
                    if (argument.Expression is IdentifierNameSyntax identifierName)
                    {
                        var parent = invocation.Parent;

                        while(!parent.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                             .Any(v => v.Identifier.Text == argument.Expression.ToString()))
                        {

                        }

                        if (variableDeclarator != null && variableDeclarator.Initializer != null)
                        {
                            var valueText = variableDeclarator.Initializer.Value.ToString();

                            if (!valueText.Contains("Builders<BsonDocument>.Filter") &&
                                !valueText.Contains("Builders<JsonDocument>.Filter"))
                            {
                                vulnerabilidades.Add(new Vulnerabilidade
                                {
                                    Tipo = tipo,
                                    Risco = risco,
                                    Detalhes = $"Vulnerabilidade encontrada na coleção {collectionName} com argumento {identifierName.Identifier.Text}."
                                });
                            }
                        }
                    }
                    else if (argument.Expression is ObjectCreationExpressionSyntax objectCreation)
                    {
                        var type = objectCreation.Type.ToString();
                        if (type != "Builders<BsonDocument>.Filter" && type != "Builders<JsonDocument>.Filter")
                        {
                            vulnerabilidades.Add(new Vulnerabilidade
                            {
                                Tipo = tipo,
                                Risco = risco,
                                Detalhes = $"Vulnerabilidade encontrada na coleção {collectionName} com argumento inseguro."
                            });
                        }
                    }
                }
            }
        }

        return vulnerabilidades;
    }

    static void AnalyzeForInsecureEncryption(SyntaxNode root) { }
    static void AnalyzeForLDAPInjection(SyntaxNode root) { }

}