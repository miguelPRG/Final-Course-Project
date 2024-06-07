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
using Windows.UI.Xaml.Media.Animation;
using System.Xml.Linq;

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
        AnalyzeForXSS(root);

        // Analisar vulnerabilidades de SQL Injection
        //var sqlVulnerabilities = AnalyzeSQLInjection(root);
        //vulnerabilities.AddRange(sqlVulnerabilities);

        return vulnerabilities; 
    }

    static void PrepararParaAdiconarVulnerabilidade(SyntaxNode node,string tipo,NivelRisco risco)
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
    static void AdicionarVulnerabilidade(string tipo, string codigo, NivelRisco risco, int linha)
    {
        object obj = new object();

        var index = vulnerabilities.IndexOf(
            vulnerabilities.FirstOrDefault(v => (v.Codigo == codigo || v.Linhas.Contains(linha)) && v.Tipo == tipo));
                       

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
    static SyntaxNode GetScopeLevel(SyntaxNode node)
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


    static void AnalyzeForSQLInjection(SyntaxNode root)
    {
        var tipo = "SQL Injection";
        var risco = NivelRisco.Alto;

        // Lista de palavras-chave SQL comuns para verificação adicional
        string[] sqlKeywords = new string[]
        {
            "select", "from", "where", "values", "update", "set", "delete",
            "create", "alter", "drop", "join", "group by", "having",
            "order by", "distinct"
        };

        // Procurar por literais de string que são parte de expressões de concatenação
        var expressions = root.DescendantNodes()
                        .OfType<BinaryExpressionSyntax>()
                        .Where(node => node.IsKind(SyntaxKind.AddExpression))
                        .Where(node => (node.Left is LiteralExpressionSyntax left && left.Token.Value is string) ||
                                       (node.Right is LiteralExpressionSyntax right && right.Token.Value is string));



        foreach (var exp in expressions)
        {
            if (exp.Parent is BinaryExpressionSyntax binaryExpression)
            {
                string expressionText = binaryExpression.ToString();
                int keywordCount = sqlKeywords.Count(keyword => expressionText.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0);

                if (keywordCount >= 2)
                {
                    // Detecção de possível vulnerabilidade
                    PrepararParaAdiconarVulnerabilidade(exp, tipo, risco);
                }
            }
        }
    }
    static void AnalyzeForXSS(SyntaxNode root)
    {
        var tipo = "XSS";
        var risco = NivelRisco.Alto; // Ajuste conforme necessário

        // Encontrar variáveis inicializadas com Request.QueryString, Request.Form, Request.Params
        var variaveis = root.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                            .Where(v => v.Right != null &&
                                        (v.Right.ToString().Contains("Request.QueryString") ||
                                         v.Right.ToString().Contains("Request.Form") ||
                                         v.Right.ToString().Contains("Request.Params") ||
                                         v.Right.ToString().Contains(".Text")) &&
                                         !v.Right.ToString().Contains("HttpUtility.HtmlEncode"))
                            .Select(v => v.Left.ToString());

        var metodos = root.DescendantNodes().OfType<MethodDeclarationSyntax>()
                          .Where(m => m.AttributeLists.ToString().Contains("[HttpPost]"));

        // Verificar se existe pelo menos uma variável encontrada
        if (!variaveis.Any() && !metodos.Any())
        {
            return;
        }

        foreach (var m in metodos)
        {
            var parametros = m.ParameterList.Parameters
                                .Select(p => p.Identifier.ToString());

            var vul = m.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                       .Where(i => variaveis.Contains(i.Right.ToString()));

            if (vul.Any())
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
            var scope = GetScopeLevel(v);

            incovations = scope.DescendantNodes().OfType<InvocationExpressionSyntax>()
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
                    //var parentScope = GetScope(inv);

                    var parentScope = GetScopeLevel(inv);

                    if (parentScope.DescendantNodes().OfType<IfStatementSyntax>()
                        .Any(ifStmt => ifStmt.Condition.ToString()
                         .Contains($"Url.IsLocalUrl({firstArgument})")))
                    {
                         PrepararParaAdiconarVulnerabilidade(inv.Parent, tipo, risco);
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
        var methodInvocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>()
                                .Where(m => m.Expression.ToString().Contains(".Find") &&
                                m.ArgumentList.Arguments.Count() > 0);

        foreach (var method in methodInvocations)
        {
            // Nome do objeto que chama aquele método
            int index = method.Expression.ToString().IndexOf(".");
            string nome = method.Expression.ToString().Substring(0, index);

            var variavel = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                .Where(v => v.Identifier.ToString() == nome);

            if (!variavel.Any())
            {
                return;
            }

            SyntaxNode parent = null; 


            if (variavel.Count() > 1)
            {
                parent = GetScopeLevel(method);

                var local = parent.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                           .FirstOrDefault(v => v.Identifier.ToString() == nome);

                if (local != null)
                {
                    variavel = new[] { local };
                }
                
                else
                {
                    variavel = new[] { variavel.First() };
                }
            }

            else
            {
                variavel = new[] { variavel.First() };
            }

            bool continuar = false;

            if (variavel.First().Initializer?.Value.ToString().Contains("GetCollection<BsonDocument>") == true)
            {
                // Se o data type for IMongoCollection<BsonDocument>
                continuar = true;
            }
            else if (variavel.First().Initializer?.Value.ToString().Contains("GetCollection<JsonDocument>") == true)
            {
                // Se o data type for IMongoCollection<JsonDocument>.
                continuar = true;
            }

            if (!continuar)
            {
                return;
            }

            var argumentos = method.ArgumentList.Arguments;

            bool isVulnerale = false;

            foreach (var arg in argumentos)
            {
                // Se o argumento contiver a seguinte expressão: Builders<BsonDocument>.Filter ou Builders<JsonDocument>.Filter
                // Ou se o argumento for identificador de nome para uma variável que tenha esse valor, chama o método PrepararParaAdicionarVulnerabilidade
                if (!arg.Expression.ToString().Contains("Builders<BsonDocument>.Filter") && 
                    !arg.Expression.ToString().Contains("Builders<JsonDocument>.Filter"))
                {
                    isVulnerale = true;
                }
                
                else if (arg.Expression is IdentifierNameSyntax identifierName)
                {
                    // Procura a definição da variável a partir deste nó para cima
                    variavel = root.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                               .Where(v => v.Identifier.ToString() == identifierName.Identifier.Text);

                    if (variavel.Count() > 1)
                    {
                        if (parent == null)
                        {
                            parent = GetScopeLevel(method);
                        }

                        var local = parent.DescendantNodes().OfType<VariableDeclaratorSyntax>()
                                   .FirstOrDefault(v => v.Identifier.ToString() == identifierName.Identifier.Text);

                        if (local != null)
                        {
                            variavel = new[] { local };
                        }
                        
                        else
                        {
                            variavel = new[] { variavel.First() };
                        }
                    }
                    
                    else
                    {
                        variavel = new[] { variavel.First() };
                    }

                    if (!variavel.First().Initializer.Value.ToString().Contains("Builders<BsonDocument>.Filter") &&
                        !variavel.First().Initializer.Value.ToString().Contains("Builders<JsonDocument>.Filter"))
                    {
                        isVulnerale = true;
                    }
                }
            }

            if (isVulnerale)
            {
                PrepararParaAdiconarVulnerabilidade(method.Parent, tipo, risco);
            }
        }
    }

    static void AnalyzeForInsecureEncryption(SyntaxNode root) { }
    static void AnalyzeForLDAPInjection(SyntaxNode root) { }

}