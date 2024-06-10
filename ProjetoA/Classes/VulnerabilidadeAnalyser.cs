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

//Site para procurrar referências: https://docs.fluidattacks.com/

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
        AnalyzeForSensitiveInformationSending(root);

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
    static bool IsStringConcatenated(ExpressionSyntax expression)
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
        else if (expression is InterpolatedStringExpressionSyntax i)
        {
            return true;
        }
        return false;
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
        /*var expressions = root.DescendantNodes()
                        .OfType<BinaryExpressionSyntax>()
                        .Where(node => node.IsKind(SyntaxKind.AddExpression))
                        .Where(node => (node.Left is LiteralExpressionSyntax left && left.Token.Value is string) ||
                                       (node.Right is LiteralExpressionSyntax right && right.Token.Value is string));*/

        var expressions = root.DescendantNodes()
                              .OfType<ExpressionSyntax>()
                              .Where(node => IsStringConcatenated(node));
        
        foreach (var exp in expressions)
        {
            //if (exp.Parent is BinaryExpressionSyntax binaryExpression)
            //{
                string expressionText = exp.ToString();
                int keywordCount = sqlKeywords.Count(keyword => expressionText.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0);

                if (keywordCount >= 2)
                {
                    // Detecção de possível vulnerabilidade
                    PrepararParaAdiconarVulnerabilidade(exp, tipo, risco);
                }
            //}
        }

        var stringsManhosas = root.DescendantNodes()
                                 .OfType<InterpolatedStringExpressionSyntax>();

        foreach (var str in stringsManhosas)
        {
           /* var stringsManhosas = root.DescendantNodes()
                                  .OfType<InterpolatedStringExpressionSyntax>()
                                  .Where(s => s.Contents.ToString().Contains());*/

            int keywordCount = sqlKeywords.Count(k => str.ToString().IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0);

            if(keywordCount >= 2)
            {
                PrepararParaAdiconarVulnerabilidade(str, tipo, risco);
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
                                        v.Right.ToString().Contains(".Text")));

        var metodos = root.DescendantNodes().OfType<MethodDeclarationSyntax>()
                          .Where(m => m.AttributeLists.ToString().Contains("[HttpPost]"));

        // Verificar se existe pelo menos uma variável encontrada
        if (!variaveis.Any() && !metodos.Any())
        {
            return;
        }

        foreach(var v in variaveis)
        {
            PrepararParaAdiconarVulnerabilidade(v.Parent, tipo, risco);
        }

        foreach (var m in metodos)
        {
            var parametros = m.ParameterList.Parameters
                                .Where(p => p.ToString().Contains("string"));

            foreach(var p in parametros)
            {
                var vulnerabilidades = m.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                           .Where(v => v.Right.ToString() == p.Identifier.ToString());
                
                foreach(var v in vulnerabilidades)
                {
                    PrepararParaAdiconarVulnerabilidade(v.Parent, tipo, risco);
                }
            }
          
        }
    }
    static void AnalyzeForCSRF(SyntaxNode root)
    {
        var tipo = "Deserialização Insegura";
        var risco = NivelRisco.Alto;

        var metodos = root.DescendantNodes().OfType<MethodDeclarationSyntax>()
                          .Where(m => m.AttributeLists.ToString().Contains("[HttpPost]") &&
                                      m.AttributeLists.ToString().Contains("[ValidateAntiForgeryToken]"));

       foreach(var m in metodos)
       {
            PrepararParaAdiconarVulnerabilidade(m, tipo, risco);
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
    static void AnalyzeLDAPInjection(SyntaxNode root)
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
                    PrepararParaAdiconarVulnerabilidade(arg, tipo, risco);
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
                            PrepararParaAdiconarVulnerabilidade(initializer, tipo, risco);
                        }
                    }
                }
            }
        }
    }
    static void AnalyzeForInsecureEncryption(SyntaxNode root) 
    {
        var tipo = "Criptografia Insegura";
        var risco = NivelRisco.Alto;

        var cripto = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>()
                         .Where(o => o.ToString().Contains("DES") ||
                                     o.ToString().Contains("RC4") ||
                                     o.ToString().Contains("MD5"));
                            
        foreach(var c in cripto)
        {
            PrepararParaAdiconarVulnerabilidade(c, tipo, risco);
        }


    }
    static void AnalyzeForSensitiveInformationSending(SyntaxNode root)
    {
        var tipo = "Envio de Informações Sensíveis";
        var risco = NivelRisco.Alto;

        var metodos = root.DescendantNodes().OfType<MethodDeclarationSyntax>()
                          .Where(m => m.AttributeLists.ToString().Contains("[HttpPost]"));

        foreach(var m in metodos)
        {

            var retorno = m.DescendantNodes().OfType<ReturnStatementSyntax>()
                           .Where(r => r.Expression.ToString().ToLower().Contains("username") ||
                                       r.Expression.ToString().ToLower().Contains("password"));

            foreach(var r in retorno)
            {
                PrepararParaAdiconarVulnerabilidade(r, tipo, risco);
            }
        }
    }

}