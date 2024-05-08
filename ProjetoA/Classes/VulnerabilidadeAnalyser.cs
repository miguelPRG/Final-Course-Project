using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Projeto.Classes;
using System.Collections.Concurrent;

namespace ProjetoA.Analyzers
{
    internal enum NivelRisco
    {
        Alto,
        Medio,
        Baixo
    }

    internal class Vulnerabilidade
    {
        public string Tipo { get; set; }
        public string Codigo { get; set; }
        public NivelRisco Risco { get; set; }

        public Vulnerabilidade(string tipo, string codigo, NivelRisco risco)
        {
            this.Tipo = tipo;
            this.Codigo = codigo;
            this.Risco = risco;
        }
    }

    internal class VulnerabilidadeAnalyzer
    {
        delegate bool Analyzer(SyntaxNode node, out string Nome);
        delegate NivelRisco Risco(SyntaxNode node);

        public async Task<List<Vulnerabilidade>> VulnerabilidadeAnalyze(SyntaxNode root)
        {
            Analyzer[] analyzers =
            {
                IsSqlInjectionVulnerable,
                IsXSSVulnerable,
                isCSRFVulnerable,
                isAuthenticationVulnerable,
                isDeserializationVulnerable,
                isLackExceptionHandelingVulnerable,
                isLackExceptionHandelingVulnerable,
                isCORSVulnerable
            };

            Risco[] riscos =
            {
                GetRiscoLevelSqlInjection,
                GetRiscoLevelXSS,
                GetRiscoLevelCSRF,
                GetRiscoLevelAuthentication,
                GetRiscoLevelDeserializacao,
                GetRiscoLevelExceptionHandeling,
                GetRiscoLevelCORS
            };

            // List to store tasks for each vulnerability check
            List<Task<Vulnerabilidade>> tasks = new List<Task<Vulnerabilidade>>();

            string nomeVulnerabilidade;
            
            foreach (var node in root.DescendantNodes())
            {
                var currentNode = node; // Store the current node in a local variable

                for(int i =0; i < analyzers.Count(); i++)
                {
                    tasks.Add(Task.Run(() =>
                    {
                        // Check for SQL Injection vulnerabilities
                        if (analyzers[i](currentNode,out nomeVulnerabilidade))
                        {
                            // Create a new Vulnerabilidade object
                            return new Vulnerabilidade
                            (
                                nomeVulnerabilidade,
                                currentNode.ToString(),
                                riscos[i](currentNode) // implement this method to determine the risk level
                            );
                        }
                            // If no vulnerability found, return null
                            return null;
                        }));
                    }
                }
      

            // Wait for all tasks to complete
            await Task.WhenAll(tasks);

            // Extract results from completed tasks
            List<Vulnerabilidade> vulnerabilities = tasks.Where(t => t.Result != null).Select(t => t.Result).ToList();

            return vulnerabilities;
        }

        bool IsSqlInjectionVulnerable(SyntaxNode node, out string Nome)
        {
            // Check for SQL Injection vulnerabilities
            // For example, check for string concatenation with user input

            Nome = "Vulnerabilidade SQL Injection";

            if (node is InvocationExpressionSyntax invocationExpression)
            {
                var methodSymbol = (IMethodSymbol)invocationExpression.Expression;
                if (methodSymbol.Name == "ExecuteNonQuery" || methodSymbol.Name == "ExecuteScalar")
                {
                    foreach (var argument in invocationExpression.ArgumentList.Arguments)
                    {
                        if (argument.Expression is BinaryExpressionSyntax binaryExpression)
                        {
                            if (binaryExpression.Left is LiteralExpressionSyntax literalExpression)
                            {
                                // Check if the literal expression contains user input
                                if (literalExpression.Token.ValueText.Contains("$"))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            return false;
        }
        NivelRisco GetRiscoLevelSqlInjection(SyntaxNode node)
        {
            // Determine the risk level based on the node
            // For example, check the method it's in, the variables involved, etc.
            if (node is InvocationExpressionSyntax invocationExpression)
            {
                var methodSymbol = (IMethodSymbol)invocationExpression.Expression;
                if (methodSymbol.Name == "ExecuteNonQuery")
                {
                    return NivelRisco.Alto;
                }
                else if (methodSymbol.Name == "ExecuteScalar")
                {
                    return NivelRisco.Medio;
                }
            }

            return NivelRisco.Baixo;
        }

        bool IsXSSVulnerable(SyntaxNode node, out string Nome) 
        {
            Nome = "Vulnerabilidade XSS";

            return true; 
        }
        NivelRisco GetRiscoLevelXSS(SyntaxNode node) 
        {  
            return NivelRisco.Alto;
        }
 
        bool isCSRFVulnerable(SyntaxNode node, out string Nome) 
        {
            Nome = "Vulnerabilidade CSRF";

            return true; 
        }
        NivelRisco GetRiscoLevelCSRF(SyntaxNode node) 
        { 
            return NivelRisco.Alto;
        }

        bool isAuthenticationVulnerable(SyntaxNode node, out string Nome) 
        {
            Nome = "Vulnerabilidade de Autenticação";

            return true; 
        }
        NivelRisco GetRiscoLevelAuthentication(SyntaxNode node) 
        {
            return NivelRisco.Alto;
        }

        bool isDeserializationVulnerable(SyntaxNode node, out string Nome) 
        {
            Nome = "Vulnerabilidade de Deserialização";
            
            return true; 
        }
        NivelRisco GetRiscoLevelDeserializacao(SyntaxNode node) 
        { 
            return NivelRisco.Alto; 
        }

        bool isLackExceptionHandelingVulnerable(SyntaxNode node, out string Nome) 
        {
            Nome = "Vulnerabilidade de Falta de Tratamento de Exceções";

            return true; 
        }
        NivelRisco GetRiscoLevelExceptionHandeling(SyntaxNode node) 
        {
            return NivelRisco.Alto; 
        }

        bool isCORSVulnerable(SyntaxNode node, out string Nome) 
        {
            Nome = "Vulnerabilidade de CORS";
            
            return true; 
        }
        NivelRisco GetRiscoLevelCORS(SyntaxNode node) 
        {   
            return NivelRisco.Alto; 
        }

    }
}